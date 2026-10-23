import sys
from datetime import datetime, timedelta, timezone

from doppel.client_api import ConnectorClient, ResultWindowExceededError
from doppel.converter_to_stix import ConverterToStix
from doppel.settings import ConnectorSettings
from doppel.utils import parse_iso_datetime
from pycti import OpenCTIConnectorHelper

LAST_RUN_FORMAT = "%Y-%m-%d %H:%M:%S"
# Attempts to page through one activity second before failing the run. Each
# retry only happens when the window's alert count changed mid-walk.
MAX_ACTIVITY_SECOND_ATTEMPTS = 3


class DoppelConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.client = ConnectorClient(self.helper, self.config)
        self.converter = ConverterToStix(
            self.helper,
            tlp_level=self.config.doppel.tlp_level,
            enable_incidents=self.config.doppel.enable_incidents,
            enable_grouping_case=self.config.doppel.enable_grouping_case,
            enable_rft_case=self.config.doppel.enable_rft_case,
        )

    def _get_last_run(self, current_state, start_datetime: datetime) -> str:
        """
        Retrieve previous run from current state or the
        start date depending on historical_polling_days from config
        :params:
            start_datetime (datetime): datetime when process started
        :return: datetime
        """
        if current_state and "last_run" in current_state:
            self.helper.connector_logger.info(
                "Resuming from last run timestamp",
                {"last_run": current_state["last_run"]},
            )
            previous_run = current_state["last_run"]
        else:
            default_start = start_datetime - timedelta(
                days=self.config.doppel.historical_polling_days
            )
            previous_run = default_start.strftime(LAST_RUN_FORMAT)
            self.helper.connector_logger.info(
                "No previous state found. Using historical polling window",
                {"start_date": previous_run},
            )

        return previous_run

    @staticmethod
    def _format_api_timestamp(last_run: str) -> str:
        """Reformat a stored last_run value as ``yyyy-mm-ddThh:mm:ss``."""
        return datetime.fromisoformat(last_run).isoformat(timespec="seconds")

    @staticmethod
    def _bisect_window(window_start: str, window_end: str) -> str:
        """Return the UTC midpoint of an activity window, truncated to seconds."""
        start = parse_iso_datetime(window_start)
        end = parse_iso_datetime(window_end)
        if start is None or end is None or start >= end:
            raise ValueError("Invalid Doppel alert activity window")

        midpoint = (start + (end - start) / 2).replace(microsecond=0)
        if midpoint <= start:
            raise ValueError(
                "Doppel alert result window exceeds the limit within one second"
            )
        return midpoint.astimezone(timezone.utc).strftime(LAST_RUN_FORMAT)

    @staticmethod
    def _next_second(timestamp: str) -> str:
        """Return the activity second after ``timestamp`` in the last_run format."""
        parsed = parse_iso_datetime(timestamp)
        if parsed is None:
            raise ValueError("Invalid Doppel alert activity timestamp")
        following = parsed.astimezone(timezone.utc) + timedelta(seconds=1)
        return following.strftime(LAST_RUN_FORMAT)

    @staticmethod
    def _is_after(timestamp: str, other: str) -> bool:
        first = parse_iso_datetime(timestamp)
        second = parse_iso_datetime(other)
        if first is None or second is None:
            raise ValueError("Invalid Doppel alert activity timestamp")
        return first > second

    @staticmethod
    def _activity_checkpoint(timestamp: object) -> str | None:
        """Truncate one activity timestamp to seconds in the last_run format."""
        parsed = parse_iso_datetime(timestamp)
        if parsed is None:
            return None
        truncated = parsed.astimezone(timezone.utc).replace(microsecond=0)
        return truncated.strftime(LAST_RUN_FORMAT)

    def _newest_activity_checkpoint(self, alerts: list) -> str:
        checkpoints = [
            checkpoint
            for checkpoint in (
                self._activity_checkpoint(alert.get("last_activity_timestamp"))
                for alert in alerts
            )
            if checkpoint is not None
        ]
        if not checkpoints:
            raise ValueError("Doppel alerts are missing last_activity_timestamp")
        return max(checkpoints)

    def _alerts_share_checkpoint(self, alerts: list, checkpoint: str) -> bool:
        """True when every alert truncates to the same activity second."""
        return all(
            self._activity_checkpoint(alert.get("last_activity_timestamp"))
            == checkpoint
            for alert in alerts
        )

    def _store_last_run(self, current_state, last_run: str):
        if current_state:
            current_state["last_run"] = last_run
        else:
            current_state = {"last_run": last_run}
        self.helper.set_state(current_state)
        self.helper.connector_logger.info(
            "Updated last run state", {"last_run": last_run}
        )
        return current_state

    def _send_alert_page(self, alerts: list, work_id: str) -> None:
        bundle = self.converter.convert_alerts_to_stix(alerts)
        bundle_sent = self.helper.send_stix2_bundle(
            bundle, work_id=work_id, cleanup_inconsistent_bundle=True
        )
        self.helper.connector_logger.info(
            "STIX bundle sent", {"len_bundle_sent": len(bundle_sent)}
        )

    def _ensure_work(self, work_id: str | None, window_end: str) -> str:
        if work_id is not None:
            return work_id
        friendly_name = f"Doppel run @ {window_end}"
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _drain_activity_second(
        self, second: str, window_end: str, work_id: str, current_state
    ):
        """
        Send every alert whose activity falls in one second using offset pages.

        Offset pages are only safe while the result set is stable. Alerts that
        receive new activity move past the window, which would shift an unseen
        alert into a page that was already fetched. Bounding the request to the
        single second keeps that set small, and any change to the window's
        total count restarts the walk from page 0 so no alert can be skipped.
        ``last_run`` stays at ``second`` until the caller moves on, so a
        failure replays this second rather than losing it.

        :return: the connector state after the last stored checkpoint
        """
        page_size = self.config.doppel.page_size
        narrow_end = self._next_second(second)
        if self._is_after(narrow_end, window_end):
            narrow_end = window_end

        for _attempt in range(MAX_ACTIVITY_SECOND_ATTEMPTS):
            baseline_count = None
            page = 0
            while True:
                try:
                    alerts, total_pages, total_count = self.client.get_alerts(
                        last_activity_timestamp=self._format_api_timestamp(second),
                        last_activity_before=self._format_api_timestamp(narrow_end),
                        page=page,
                        page_size=page_size,
                    )
                except ResultWindowExceededError as err:
                    raise RuntimeError(
                        "Doppel alert result window exceeded within a single "
                        "activity second"
                    ) from err

                if baseline_count is None:
                    baseline_count = total_count
                elif total_count != baseline_count:
                    self.helper.connector_logger.warning(
                        "[DoppelConnector] Alert activity second changed while "
                        "paging; restarting from the first page",
                        {
                            "last_activity_timestamp": second,
                            "last_activity_before": narrow_end,
                            "page": page,
                            "previous_count": baseline_count,
                            "count": total_count,
                        },
                    )
                    break

                if not alerts:
                    return current_state

                # Validate before any OpenCTI side effect.
                self._newest_activity_checkpoint(alerts)
                self._send_alert_page(alerts, work_id)
                current_state = self._store_last_run(current_state, second)

                if len(alerts) < page_size or page + 1 >= total_pages:
                    return current_state
                page += 1

        raise RuntimeError(
            "Doppel alerts kept changing while paging a single activity second"
        )

    def process_message(self) -> None:
        """
        Connector main process to collect alerts.

        Each page is converted and sent before the next page is requested.
        ``last_run`` advances after every successful send to that page's
        newest activity time so a later failure resumes from the last page
        that was stored. Every page is requested as page 0 from the inclusive
        lower bound, so alerts that gain activity mid-run cannot shift unseen
        alerts into an already fetched page. When a full page shares one
        activity second, that second is drained separately with a bounded
        window and count verification. If Doppel rejects a result window above
        its limit, the connector bisects the window until the oldest bounded
        range can be processed safely.
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Running scheduled fetch")
        work_id = None
        start_datetime = datetime.now(tz=timezone.utc)
        current_state = self.helper.get_state()

        try:
            cursor = self._get_last_run(current_state, start_datetime)
            window_end = start_datetime.strftime(LAST_RUN_FORMAT)
            page_size = self.config.doppel.page_size

            while not self._is_after(cursor, window_end):
                try:
                    alerts, _total_pages, _total_count = self.client.get_alerts(
                        last_activity_timestamp=self._format_api_timestamp(cursor),
                        last_activity_before=self._format_api_timestamp(window_end),
                        page=0,
                        page_size=page_size,
                    )
                except ResultWindowExceededError:
                    previous_window_end = window_end
                    window_end = self._bisect_window(cursor, window_end)
                    self.helper.connector_logger.warning(
                        "[DoppelConnector] Narrowing oversized alert activity window",
                        {
                            "last_activity_timestamp": cursor,
                            "previous_last_activity_before": previous_window_end,
                            "last_activity_before": window_end,
                        },
                    )
                    continue

                if not alerts:
                    break

                # Validate the page checkpoint before creating OpenCTI work or
                # sending data. Otherwise an invalid page could be delivered
                # without advancing state and replay forever on later runs.
                checkpoint = self._newest_activity_checkpoint(alerts)
                if self._is_after(cursor, checkpoint):
                    raise ValueError(
                        "Doppel returned alerts older than the requested activity "
                        "window"
                    )
                page_is_full = len(alerts) >= page_size

                if page_is_full and self._alerts_share_checkpoint(alerts, checkpoint):
                    # More alerts than one page share this second. Re-read the
                    # second through a bounded, count-verified walk instead of
                    # trusting offset pages over a mutable ordering.
                    self.helper.connector_logger.info(
                        "[DoppelConnector] Full page shares one activity second; "
                        "draining that second separately",
                        {"last_activity_timestamp": checkpoint},
                    )
                    work_id = self._ensure_work(work_id, window_end)
                    current_state = self._drain_activity_second(
                        checkpoint, window_end, work_id, current_state
                    )
                    cursor = self._next_second(checkpoint)
                    continue

                work_id = self._ensure_work(work_id, window_end)
                self._send_alert_page(alerts, work_id)

                # Persist after every successful send so a later page failure
                # does not replay pages already delivered.
                current_state = self._store_last_run(current_state, checkpoint)
                cursor = checkpoint
                if not page_is_full:
                    break

            self._store_last_run(current_state, window_end)
            if work_id:
                message = f"{self.helper.connect_name} connector successfully run"
                self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "[DoppelConnector] Error in process_message", {"error": err}
            )
            if work_id:
                message = (
                    f"{self.helper.connect_name} connector failed to process alerts: "
                    f"{err}"
                )
                self.helper.api.work.to_processed(work_id, message, in_error=True)

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Starting scheduler")
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
