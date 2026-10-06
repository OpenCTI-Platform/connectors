import gzip
import json
import threading

import requests
from connector.settings import ConnectorSettings
from connector.utils import indicator_id_from_event
from pycti import OpenCTIConnectorHelper
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

BATCH_FLUSH_INTERVAL_SECONDS = 30
BATCH_SIZE = 10000


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, requests.HTTPError):
        return exc.response is not None and exc.response.status_code >= 500
    return isinstance(exc, requests.RequestException)


class DatadogIntelClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        indicator_type: str,
    ):
        """
        Args:
            helper: Used for logging.
            config: Connector settings; supplies the API base URL, API key, and application key.
            indicator_type: The indicator type this client handles (e.g. ``"ip_address"``).
        """
        self.helper = helper
        self.indicator_type = indicator_type
        self.integration_api_url = str(config.datadog_intel.integration_api_url).rstrip(
            "/"
        )

        headers = {
            "dd-api-key": config.datadog_intel.dd_api_key.get_secret_value(),
            "dd-application-key": config.datadog_intel.dd_application_key.get_secret_value(),
            "Content-Type": "application/json",
            "ti_vendor": "opencti",
            "ti_indicator": indicator_type,
            "ti_integration_account": "00000000-0000-0000-0000-000000000000",
        }

        self.session = requests.Session()
        self.session.headers.update(headers)

        self.batch: dict[str, dict] = {}
        self.batch_lock = threading.Lock()
        self.flush_lock = threading.Lock()
        self._flush_timer: threading.Timer | None = None

    ###########################################################
    # API methods
    ###########################################################

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(initial=1, max=60, jitter=5),
        retry=retry_if_exception(_is_retryable),
        before_sleep=lambda s: s.args[0].helper.connector_logger.warning(
            "Retrying POST to endpoint",
            meta={
                "attempt": s.attempt_number,
                "error": str(s.outcome.exception()),
            },
        ),
        reraise=True,
    )
    def _post_indicators(self, payload: str) -> None:
        gzipped_body = gzip.compress(payload.encode("utf-8"))
        self.session.headers["Content-Encoding"] = "gzip"

        response = self.session.post(
            self.integration_api_url,
            data=gzipped_body,
            timeout=30,
        )
        self.helper.connector_logger.debug(
            "POST response",
            meta={
                "status_code": response.status_code,
                "url": self.integration_api_url,
            },
        )
        response.raise_for_status()

    ###########################################################
    # Flush / Batch methods
    ###########################################################

    def _append_to_batch(self, data: dict) -> None:
        indicator_id = indicator_id_from_event(data)
        if indicator_id is None:
            self.helper.connector_logger.error(
                "Indicator ID is missing",
                meta={"raw": data},
            )
            return

        with self.batch_lock:
            if indicator_id not in self.batch:
                self.batch[indicator_id] = data
                return
            if self.batch[indicator_id].get("modified", "") < data.get("modified", ""):
                self.batch[indicator_id] = data

            # There is an edge case where if a customer creates an indicator and deletes it before the indicator creation was flushed,
            # the event `x_opencti_event_type` won't be updated because modified field has not changed
            # In this scenario we will keep the `x_opencti_event_type:delete`
            if data["x_opencti_event_type"] == "delete":
                self.batch[indicator_id]["x_opencti_event_type"] = "delete"

    def _flush_batch(self) -> None:
        with self.flush_lock:
            self._flush_batch_locked()

    def _flush_batch_locked(self) -> None:
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None

        # Snapshot the current batch under the lock so the HTTP POST
        # below can happen WITHOUT holding ``batch_lock``. The
        # previous shape held the lock for the full retry cycle (up
        # to ~60 s of exponential backoff during a Datadog outage),
        # blocking every incoming ``_append_to_batch`` call and
        # serialising the timer-driven flushes against
        # ``process_indicator``. The shallow ``dict(self.batch)`` copy
        # keeps the value references shared with the live batch — so
        # if a concurrent ``_append_to_batch`` REPLACES one of the
        # entries during the POST, we can detect it with an
        # identity check below and leave the new state in the batch
        # for the next flush instead of discarding it.
        with self.batch_lock:
            if not self.batch:
                return
            snapshot = dict(self.batch)
            snapshot_count = len(snapshot)

        self.helper.connector_logger.info(
            "Flushing batch",
            meta={
                "count": snapshot_count,
                "indicator_type": self.indicator_type,
            },
        )

        try:
            self._post_indicators(json.dumps(list(snapshot.values())))
        except requests.RequestException as exc:
            self.helper.connector_logger.error(
                "Failed to push batch after all retries",
                meta={"error": str(exc), "url": self.integration_api_url},
            )
            # Drop the batch when it has grown past BATCH_SIZE so a
            # prolonged Datadog outage cannot blow OpenCTI's worker
            # memory; otherwise keep the in-memory contents AND
            # reschedule a fresh timer so retained events are retried
            # once the endpoint recovers, even if no new events
            # arrive to drive a flush.
            with self.batch_lock:
                if len(self.batch) >= BATCH_SIZE:
                    self.helper.connector_logger.error(
                        "Dropping batch — size limit reached while endpoint is unreachable",
                        meta={"count": len(self.batch)},
                    )
                    self.batch = {}
                else:
                    self._reset_flush_timer()
            return

        self.helper.connector_logger.info(
            "Batch flushed",
            meta={
                "count": snapshot_count,
                "indicator_type": self.indicator_type,
            },
        )
        # Remove only the entries we actually pushed; new events that
        # arrived during the POST stay in the batch for the next
        # flush. Identity comparison detects replacements made by
        # ``_append_to_batch`` (which always assigns a fresh dict
        # ref) — in-place mutations on the same dict (e.g. the
        # "create-then-delete-mid-flight" edge case in
        # ``_append_to_batch``) are already reflected in the
        # snapshot we just posted, so removing the entry here is
        # correct in that case too.
        with self.batch_lock:
            for ind_id, sent_value in snapshot.items():
                current = self.batch.get(ind_id)
                if current is sent_value:
                    self.batch.pop(ind_id, None)

    def _reset_flush_timer(self) -> None:
        if self._flush_timer is not None:
            self._flush_timer.cancel()
        self._flush_timer = threading.Timer(
            BATCH_FLUSH_INTERVAL_SECONDS, self._on_flush_timeout
        )
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _on_flush_timeout(self) -> None:
        self.helper.connector_logger.debug(
            "Flush timeout reached, flushing remaining batch"
        )
        self._flush_batch()

    ###########################################################
    # Process indicator method
    ###########################################################
    def process_indicator(self, data: dict) -> None:
        self.helper.connector_logger.debug("Processing batch event", meta={"raw": data})

        self._append_to_batch(data)

        with self.batch_lock:
            batch_size = len(self.batch)

        if batch_size >= BATCH_SIZE:
            self._flush_batch()

        # Reset the flush timer regardless of the batch size
        # If the time expires, the batch will be flushed automatically
        self._reset_flush_timer()
