import sys
import traceback
from datetime import UTC, datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from shadowserver.settings import ConnectorSettings


class ExternalImportConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
    """

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: ConnectorSettings
    ) -> None:
        self.helper = helper
        self.config = config
        self.start_time = datetime.now(tz=UTC)  # Needs to be reset for each run
        self.pending_work_ids: set[str] = set()

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def update_state(self, **kwargs: Any) -> None:
        self.helper.set_state(state={**self.state, **kwargs})

    def log_last_run(self) -> datetime | None:
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)  # For retro compatibility
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
            message = f"last run @ {last_run.isoformat(timespec='seconds')}"
        else:
            message = "has never run"
        self.helper.connector_logger.info(
            f"{self.helper.connect_name} connector {message}"
        )
        self.helper.connector_logger.info(f"{self.helper.connect_name} will run!")
        return last_run

    def set_last_run(self):
        # Store the current timestamp as a last run
        self.helper.connector_logger.info(
            f"{self.helper.connect_name} connector successfully run, storing last_run as "
            + str(self.start_time.isoformat(timespec="seconds"))
        )
        self.helper.connector_logger.debug(
            f"Grabbing current state and update it with last_run: {self.start_time.isoformat(timespec='seconds')}"
        )
        self.update_state(last_run=self.start_time.isoformat(timespec="seconds"))
        self.helper.connector_logger.info(
            f"Last_run stored, next run in: {str(self.config.connector.duration_period)}"
        )

    def process_data(self):
        # Performing the collection of intelligence
        for bundle_objects, date_str in self._collect_intelligence():
            if not bundle_objects:
                self.helper.connector_logger.info(
                    f"No data to send to OpenCTI for {date_str}."
                )
                continue
            work_id = self.helper.api.work.initiate_work(
                connector_id=self.helper.connect_id,
                friendly_name=f"{self.helper.connect_name} run @ {self.start_time.strftime('%Y-%m-%dT%H:%M:%S')} for {date_str}",
            )
            self.pending_work_ids.add(work_id)

            bundle = self.helper.stix2_create_bundle(items=bundle_objects)

            self.helper.connector_logger.info(
                f"Sending {len(bundle_objects)} STIX objects to OpenCTI for {date_str}..."
            )
            self.helper.send_stix2_bundle(
                bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            self.helper.api.work.to_processed(
                work_id, f"Connector successfully run for {date_str}"
            )
            self.pending_work_ids.discard(work_id)

    def process_message(self):
        self.log_last_run()
        self.process_data()
        self.set_last_run()

    def process(self):
        self.start_time = datetime.now(tz=UTC)
        self.pending_work_ids.clear()
        has_error = False

        meta = {"connector_name": self.helper.connect_name}
        try:
            self.helper.connector_logger.info("Running connector...", meta=meta)
            self.process_message()
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector ended"
            )
        except (KeyboardInterrupt, SystemExit):
            has_error = True
            self.helper.connector_logger.info("Connector stopped by user.", meta=meta)
            sys.exit(0)
        except Exception as e:
            has_error = True
            traceback.print_exc()
            meta["error"] = str(e)
            self.helper.connector_logger.error(f"Unexpected error: {e}", meta=meta)
        finally:
            if self.pending_work_ids:
                message = (
                    "Connector stopped before processing completion"
                    if has_error
                    else "Connector successfully run"
                )
                for pending_work_id in list(self.pending_work_ids):
                    self.helper.api.work.to_processed(
                        pending_work_id,
                        message,
                        has_error,
                    )
                    self.pending_work_ids.discard(pending_work_id)

    def run(self) -> None:
        # Main procedure
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} connector..."
        )
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    def _collect_intelligence(self) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError
