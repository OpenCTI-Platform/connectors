import sys
import time
import traceback
from datetime import UTC, datetime

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

    def _collect_intelligence(self) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError

    def process_message(self):
        # Get the current timestamp and check
        timestamp = int(time.time())
        current_state = self.helper.get_state()
        if current_state is not None and "last_run" in current_state:
            last_run = current_state["last_run"]
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector last run @ {datetime.fromtimestamp(last_run, tz=UTC).isoformat()}"
            )
        else:
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector has never run"
            )

        self.helper.connector_logger.info(f"{self.helper.connect_name} will run!")
        friendly_name = f"{self.helper.connect_name} run @ {datetime.fromtimestamp(timestamp, tz=UTC).isoformat()}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        # Performing the collection of intelligence
        bundle_objects = self._collect_intelligence()
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()

            self.helper.connector_logger.info(
                f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
            )
            self.helper.send_stix2_bundle(
                bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
        else:
            self.helper.connector_logger.info("No data to send to OpenCTI.")

        # Store the current timestamp as a last run
        message = (
            f"{self.helper.connect_name} connector successfully run, storing last_run as "
            + str(timestamp)
        )
        self.helper.connector_logger.info(message)

        self.helper.connector_logger.debug(
            f"Grabbing current state and update it with last_run: {timestamp}"
        )
        current_state = self.helper.get_state()
        if current_state:
            current_state["last_run"] = timestamp
        else:
            current_state = {"last_run": timestamp}
        self.helper.set_state(current_state)

        self.helper.api.work.to_processed(work_id, message)
        self.helper.connector_logger.info(
            "Last_run stored, next run in: "
            + str(
                round(
                    self.config.connector.duration_period.total_seconds() / 3600,
                    2,
                )
            )
            + " hours"
        )

    def process(self):
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

    def run(self) -> None:
        # Main procedure
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} connector..."
        )
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
