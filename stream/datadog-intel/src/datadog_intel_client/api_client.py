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
        self.integration_api_url = config.datadog_intel.integration_api_url

        headers = {
            "dd-api-key": config.datadog_intel.dd_api_key,
            "dd-application-key": config.datadog_intel.dd_application_key,
            "Content-Type": "application/json",
            "ti_vendor": "opencti",
            "ti_indicator": indicator_type,
            "ti_integration_account": "00000000-0000-0000-0000-000000000000",
        }

        self.session = requests.Session()
        self.session.headers.update(headers)

        self.batch: dict[str, dict] = {}
        self.batch_lock = threading.Lock()
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
            {"attempt": s.attempt_number, "error": str(s.outcome.exception())},
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
            {"status_code": response.status_code, "url": self.integration_api_url},
        )
        response.raise_for_status()

    ###########################################################
    # Flush / Batch methods
    ###########################################################

    def _append_to_batch(self, data: dict) -> None:
        indicator_id = indicator_id_from_event(data)
        if indicator_id is None:
            self.helper.connector_logger.error("Indicator ID is missing", {"raw": data})
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
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None
        with self.batch_lock:
            if not self.batch:
                return
            self.helper.connector_logger.info(
                "Flushing batch",
                {"count": len(self.batch), "indicator_type": self.indicator_type},
            )

            try:
                self._post_indicators(json.dumps(list(self.batch.values())))
            except requests.RequestException as e:
                self.helper.connector_logger.error(
                    "Failed to push batch after all retries",
                    {"error": str(e), "url": self.integration_api_url},
                )
                # Drop the batch if it has grown beyond BATCH_SIZE to avoid unbounded memory
                # consumption on the OpenCTI instance during a Datadog outage.
                if len(self.batch) >= BATCH_SIZE:
                    self.helper.connector_logger.error(
                        "Dropping batch — size limit reached while endpoint is unreachable",
                        {"count": len(self.batch)},
                    )
                    self.batch = {}
                else:
                    # Reschedule so the retained batch is retried once the endpoint recovers,
                    # even if no new indicators arrive to trigger a flush.
                    self._reset_flush_timer()
                return
            self.helper.connector_logger.info(
                "Batch flushed",
                {"count": len(self.batch), "indicator_type": self.indicator_type},
            )
            self.batch = {}

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
        self.helper.connector_logger.debug("Processing batch event", {"raw": data})

        self._append_to_batch(data)

        with self.batch_lock:
            batch_size = len(self.batch)

        if batch_size >= BATCH_SIZE:
            self._flush_batch()

        # Reset the flush timer regardless of the batch size
        # If the time expires, the batch will be flushed automatically
        self._reset_flush_timer()
