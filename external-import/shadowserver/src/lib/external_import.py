import sys
import traceback
from datetime import UTC, datetime
from functools import cached_property
from typing import Any

import stix2
from pycti import OpenCTIConnectorHelper
from shadowserver.config import ConnectorSettings


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
        self.start_time = datetime.now()  # Needs to be reset for each run
        self.work_id = None

    @cached_property
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
        if not (bundle_objects := self._collect_intelligence()):
            self.helper.connector_logger.info("No data to send to OpenCTI.")
            return
        self.work_id = self.helper.api.work.initiate_work(
            connector_id=self.helper.connect_id,
            friendly_name=f"{self.helper.connect_name} run @ {self.start_time.isoformat(timespec='seconds')}",
        )

        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()

        self.helper.connector_logger.info(
            f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
        )
        self.helper.send_stix2_bundle(
            bundle,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )

    def process_message(self):
        self.log_last_run()
        self.process_data()
        self.set_last_run()

    def process(self):
        self.start_time = datetime.now(UTC)

        meta = {"connector_name": self.helper.connect_name}
        try:
            self.helper.connector_logger.info("Running connector...", meta=meta)
            self.process_message()
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector ended"
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.", meta=meta)
            sys.exit(0)
        except Exception as e:
            traceback.print_exc()
            meta["error"] = str(e)
            self.helper.connector_logger.error(f"Unexpected error: {e}", meta=meta)
        finally:
            if self.work_id:
                self.helper.api.work.to_processed(
                    self.work_id, "Connector successfully run"
                )

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
