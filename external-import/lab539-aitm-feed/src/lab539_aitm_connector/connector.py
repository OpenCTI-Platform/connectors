"""Lab539 AiTM Feed OpenCTI connector."""

import sys
from datetime import datetime, timedelta, timezone

from pycti import OpenCTIConnectorHelper

from .api_client import AiTMFeedClient
from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings


class Lab539AiTMConnector:
    """OpenCTI External Import connector for the Lab539 AiTM Feed."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = AiTMFeedClient(
            api_key=self.config.aitm_feed.api_key,
            base_url=self.config.aitm_feed.api_base_url,
        )
        self.converter = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.aitm_feed.tlp_level,
        )

    def _get_last_run(self) -> int | None:
        """Retrieve last run as a Unix timestamp from connector state."""
        state = self.helper.get_state()
        if state and "last_run" in state:
            value = state["last_run"]
            if isinstance(value, int):
                return value
            return int(datetime.fromisoformat(value).timestamp())
        return None

    def _set_last_run(self, now: datetime) -> None:
        """Store last run timestamp in connector state."""
        state = self.helper.get_state() or {}
        state["last_run"] = now.isoformat(timespec="seconds")
        self.helper.set_state(state)

    def _is_new_data_available(self, current_event_id: str | None) -> bool:
        """Decide whether to pull the full dataset based on the latest eventid."""
        state = self.helper.get_state()
        last_event_id = state.get("last_event_id") if state else None

        if current_event_id is None:
            return True
        if last_event_id is None:
            return True
        return current_event_id != last_event_id

    def _update_last_event_id(self, current_event_id: str | None) -> None:
        """Store the current latest eventid in connector state."""
        if current_event_id:
            state = self.helper.get_state() or {}
            state["last_event_id"] = current_event_id
            self.helper.set_state(state)

    def process_message(self) -> None:
        """Execute a single connector run."""
        self.helper.connector_logger.info(f"{self.config.connector.name}: Starting run")

        # Fetch the latest eventid once and reuse it both for the pre-check and
        # for the state update after a successful import, to avoid a second
        # last-event API call per run.
        current_event_id = self.client.get_last_event()
        if not self._is_new_data_available(current_event_id):
            self.helper.connector_logger.info(
                f"{self.config.connector.name}: No new data available, skipping run"
            )
            return

        now = datetime.now(tz=timezone.utc)
        last_run = self._get_last_run()
        work_id = None

        try:
            if last_run is None:
                lookback_days = self.config.aitm_feed.first_run_lookback_days
                lookback_after = int((now - timedelta(days=lookback_days)).timestamp())
                self.helper.connector_logger.info(
                    f"{self.config.connector.name}: First run, pulling "
                    f"{lookback_days} days of data"
                )
                records = self.client.get_records(after=lookback_after)
            else:
                self.helper.connector_logger.info(
                    f"{self.config.connector.name}: Pulling records since "
                    f"{datetime.fromtimestamp(last_run, tz=timezone.utc).isoformat()}"
                )
                records = self.client.get_records(after=last_run)

        except RuntimeError as e:
            self.helper.connector_logger.error(
                f"{self.config.connector.name}: Failed to fetch records",
                meta={"error": str(e)},
            )
            return

        if not records:
            self.helper.connector_logger.info(
                f"{self.config.connector.name}: No records returned from API"
            )
            self._set_last_run(now)
            return

        self.helper.connector_logger.info(
            f"{self.config.connector.name}: Processing {len(records)} records"
        )

        try:
            bundle = self.converter.records_to_bundle(records)
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.helper.connector_logger.error(
                f"{self.config.connector.name}: Failed to convert records to STIX",
                meta={"error": str(e)},
            )
            return

        try:
            friendly_name = (
                f"{self.config.connector.name} - "
                f"{now.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.send_stix2_bundle(
                bundle.serialize(pretty=False),
                work_id=work_id,
            )
            self.helper.api.work.to_processed(
                work_id, f"{self.config.connector.name} import complete"
            )
            self.helper.connector_logger.info(
                f"{self.config.connector.name}: Successfully imported "
                f"{len(records)} records into OpenCTI"
            )
            work_id = None

        except Exception as e:  # pylint: disable=broad-exception-caught
            self.helper.connector_logger.error(
                f"{self.config.connector.name}: Failed to send bundle to OpenCTI",
                meta={"error": str(e)},
            )
            if work_id is not None:
                try:
                    self.helper.api.work.to_processed(
                        work_id, f"Unhandled exception: {e}", in_error=True
                    )
                except Exception as close_err:  # pylint: disable=broad-exception-caught
                    self.helper.connector_logger.error(
                        f"{self.config.connector.name}: Failed to mark work as in_error",
                        meta={"work_id": work_id, "error": str(close_err)},
                    )
            return

        self._set_last_run(now)
        self._update_last_event_id(current_event_id)

    def run(self) -> None:
        """Start the connector scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )

    @staticmethod
    def handle_interrupt() -> None:
        """Handle keyboard interrupt gracefully."""
        sys.exit(0)
