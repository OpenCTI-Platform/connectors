import sys
from datetime import datetime, timedelta, timezone

from doppel.client_api import ConnectorClient
from doppel.converter_to_stix import ConverterToStix
from doppel.settings import ConnectorSettings
from doppel.utils import parse_iso_datetime
from pycti import OpenCTIConnectorHelper


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

    def _get_last_run(self, current_state, start_datetime: datetime) -> datetime:
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
            previous_run = default_start.strftime("%Y-%m-%d %H:%M:%S")
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
    def _activity_checkpoint(timestamp: object) -> str | None:
        """Truncate one activity timestamp to seconds in the last_run format."""
        parsed = parse_iso_datetime(timestamp)
        if parsed is None:
            return None
        truncated = parsed.astimezone(timezone.utc).replace(microsecond=0)
        return truncated.strftime("%Y-%m-%d %H:%M:%S")

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

    def process_message(self) -> None:
        """
        Connector main process to collect alerts.

        Each page is converted and sent before the next page is requested.
        ``last_run`` advances after every successful send to that page's
        newest activity time so a later failure resumes from the last page
        that was stored. The lower bound is inclusive, so a full page whose
        alerts all share that timestamp keeps the in-memory cursor and
        requests the next page instead of repeating the same page forever.
        :return: None
        """
        self.helper.connector_logger.info("[DoppelConnector] Running scheduled fetch")
        work_id = None
        start_datetime = datetime.now(tz=timezone.utc)
        current_state = self.helper.get_state()

        try:
            cursor = self._get_last_run(current_state, start_datetime)
            window_end = start_datetime.strftime("%Y-%m-%d %H:%M:%S")
            page = 0
            page_size = self.config.doppel.page_size

            while True:
                alerts, _total_pages = self.client.get_alerts(
                    last_activity_timestamp=self._format_api_timestamp(cursor),
                    last_activity_before=self._format_api_timestamp(window_end),
                    page=page,
                    page_size=page_size,
                )
                if not alerts:
                    break

                if work_id is None:
                    friendly_name = f"Doppel run @ {window_end}"
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                self._send_alert_page(alerts, work_id)

                checkpoint = self._newest_activity_checkpoint(alerts)
                # Persist after every successful send so a later page failure
                # does not replay pages already delivered.
                current_state = self._store_last_run(current_state, checkpoint)
                page_is_full = len(alerts) >= page_size
                if page_is_full and self._alerts_share_checkpoint(alerts, checkpoint):
                    self.helper.connector_logger.info(
                        "[DoppelConnector] Full page shares one activity timestamp; "
                        "fetching the next page",
                        {"page": page, "last_activity_timestamp": checkpoint},
                    )
                    # Keep the in-memory cursor unchanged so the inclusive lower
                    # bound still pages through alerts that share this timestamp.
                    page += 1
                    continue

                cursor = checkpoint
                page = 0
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
