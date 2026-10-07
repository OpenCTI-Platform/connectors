import sys
import time
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings


class ExternalImportConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (int): The interval between two runs, in seconds (from `CONNECTOR_DURATION_PERIOD`).
    """

    def __init__(self):
        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

        # Specific connector attributes for external import connectors
        self.interval = int(self.config.connector.duration_period.total_seconds())

    def _collect_intelligence(self) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector, in seconds."""
        return self.interval

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    last_run_datetime = (
                        datetime.fromtimestamp(last_run).replace(tzinfo=timezone.utc)
                        if last_run
                        else None
                    )

                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    try:
                        # Performing the collection of intelligence
                        bundle_objects = self._collect_intelligence(
                            since=last_run_datetime
                        )
                        if bundle_objects:
                            bundle = self.helper.stix2_create_bundle(bundle_objects)

                            self.helper.log_info(
                                f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                            )
                            self.helper.send_stix2_bundle(
                                bundle,
                                work_id=work_id,
                                cleanup_inconsistent_bundle=True,
                            )

                    except Exception as e:
                        self.helper.log_error(str(e))

                    # Store the current timestamp as a last run
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.log_info(message)

                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {timestamp}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = timestamp
                    else:
                        current_state = {"last_run": timestamp}
                    self.helper.set_state(current_state)

                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self._get_interval() / 60 / 60, 2))
                        + " hours"
                    )
                else:
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60, 2))
                        + " hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)
