import os
import sys
import time
from datetime import datetime

from pycti import OpenCTIConnectorHelper


class ExternalImportConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        interval (str): The interval to use. It SHOULD be a string in the format '7d', '12h', '10m', '30s'
                        where the final letter SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        # Specific connector attributes for external import connectors
        try:
            self.interval = os.environ.get("CONNECTOR_RUN_EVERY", None).lower()
            self.helper.log_info(
                f"Verifying integrity of the CONNECTOR_RUN_EVERY value: '{self.interval}'"
            )
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as ex:
            msg = (
                f"Error ({ex}) when grabbing CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. "
                "It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter "
                "SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            )
            self.helper.log_error(msg)
            raise ValueError(msg) from ex

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            self.update_existing_data = update_existing_data.lower() == "true"
        elif isinstance(update_existing_data, bool) and update_existing_data.lower in [
            True,
            False,
        ]:
            self.update_existing_data = update_existing_data
        else:
            msg = (
                f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. "
                "It SHOULD be either `true` or `false`. `false` is assumed."
            )
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def _collect_intelligence(self) -> list:
        """Collect intelligence from the source"""
        raise NotImplementedError

    def _get_interval(self) -> int:
        """Returns the interval to use for the connector

        This SHOULD always return the interval in seconds. If the connector expects
        the parameter to be received as hours uncomment as necessary.
        """
        unit = self.interval[-1:]
        value = self.interval[:-1]

        try:
            if unit == "d":
                # In days:
                return int(value) * 60 * 60 * 24
            if unit == "h":
                # In hours:
                return int(value) * 60 * 60
            if unit == "m":
                # In minutes:
                return int(value) * 60
            if unit == "s":
                # In seconds:
                return int(value)
        except Exception as ex:
            self.helper.log_error(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(ex)}"
            )
            raise ValueError(
                f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{self.interval}'. {str(ex)}"
            ) from ex

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
                        f'{datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")}'
                    )
                else:
                    last_run = None
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                # If the last_run is more than interval-1 day
                if last_run is None or ((timestamp - last_run) >= self._get_interval()):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    self.helper.log_info(f"{self.helper.connect_name} will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = f'{self.helper.connect_name} run @ {now.strftime("%Y-%m-%d %H:%M:%S")}'
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    try:
                        # Performing the collection of intelligence
                        self._collect_intelligence()

                    except Exception as e:
                        self.helper.log_error(str(e))

                    # Store the current timestamp as a last run
                    message = f"{self.helper.connect_name} connector successfully run, storing last_run as {timestamp}"
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
                        f"Last_run stored, next run in: {round(self._get_interval() / 60 / 60, 2)} hours"
                    )
                else:
                    self.helper.metric.state("idle")
                    new_interval = self._get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, "
                        f"next run in: {round(new_interval / 60 / 60, 2)} hours"
                    )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.metric.inc("error_count")
                self.helper.metric.state("stopped")
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                sys.exit(0)

            time.sleep(60)
