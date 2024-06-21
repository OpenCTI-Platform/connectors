import os
import sys
import time
from datetime import UTC, datetime
from typing import Dict

import stix2
from collectors.builder import build_collectors
from collectors.collector import Collector
from pycti import OpenCTIConnectorHelper
from time_.interval import delta_from_interval, seconds_from_interval
from zerofox.app.zerofox import ZeroFox

ZEROFOX_REFERENCE = stix2.ExternalReference(
    source_name="ZeroFox Threat Intelligence",
    url="https://www.zerofox.com/threat-intelligence/",
    description="ZeroFox provides comprehensive, accurate, and timely intelligence bundles through its API.",
)


class ZeroFoxConnector:
    def __init__(self):
        """ZeroFox connector for OpenCTI."""
        self.helper = OpenCTIConnectorHelper({})

        # Specific connector attributes for external import connectors
        self.interval = os.environ.get("CONNECTOR_RUN_EVERY", "1d").lower()
        self._validate_interval("CONNECTOR_RUN_EVERY", self.interval)

        self.first_run_interval = os.environ.get("CONNECTOR_FIRST_RUN", "1d").lower()
        self._validate_interval("CONNECTOR_FIRST_RUN", self.first_run_interval)

        self.update_existing_data = self._parse_update_existing_data(
            os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        )

        self.zerofox_username = os.environ.get("ZEROFOX_USERNAME", "")
        self.zerofox_password = os.environ.get("ZEROFOX_PASSWORD", "")
        self.client = ZeroFox(user=self.zerofox_username, token=self.zerofox_password)

        self.collectors: Dict[str, Collector] = build_collectors(
            client=self.client,
            feeds=os.environ.get("ZEROFOX_COLLECTORS", None),
            logger=self.helper.connector_logger,
        )

    def _validate_interval(self, env_var, interval):
        self.helper.log_info(
            f"Verifying integrity of the {env_var} value: '{interval}'"
        )
        try:
            unit = self.interval[-1]
            if unit not in ["d", "h", "m", "s"]:
                raise TypeError
            int(self.interval[:-1])
        except TypeError as ex:
            msg = (
                f"Error ({ex}) when grabbing {env_var} environment variable: '{interval}'. "
                "It SHOULD be a string in the format '7d', '12h', '10m', '30s' where the final letter "
                "SHOULD be one of 'd', 'h', 'm', 's' standing for day, hour, minute, second respectively. "
            )
            self.helper.log_error(msg)
            raise ValueError(msg) from ex

    def _parse_update_existing_data(self, update_existing_data):
        if isinstance(update_existing_data, str) and update_existing_data.lower() in [
            "true",
            "false",
        ]:
            return update_existing_data.lower() == "true"
        elif isinstance(update_existing_data, bool) and update_existing_data in [
            True,
            False,
        ]:
            return update_existing_data
        else:
            msg = (
                f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{update_existing_data}'. "
                "It SHOULD be either `true` or `false`. `false` is assumed. "
            )
            self.helper.log_warning(msg)
            return False

    def send_bundle(self, work_id, bundle_objects):
        bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()

        self.helper.log_info(
            f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
        )
        self.helper.send_stix2_bundle(
            bundle,
            update=self.update_existing_data,
            work_id=work_id,
        )

    def collect_intelligence_for_endpoint(
        self,
        current_time: int,
        last_run,
        collector_name: str,
        collector: Collector,
    ):

        self.helper.log_debug(f"Collector name: {collector_name}")
        self.helper.log_debug(f"Last run: {last_run}")
        self.helper.log_debug(f"Current time: {current_time}")
        if last_run is not None:
            self.helper.log_debug(f"Difference (Seconds): {current_time - last_run}")
        self.helper.log_debug(
            f"Collector Interval (Seconds): {seconds_from_interval(self.interval)}"
        )

        if last_run is None:
            self.helper.log_info(
                f"{self.helper.connect_name} will run on endpoint {collector_name}!"
            )
            last_run_date = datetime.now(UTC) - delta_from_interval(
                self.first_run_interval
            )
            last_run = last_run_date.timestamp()
        elif (current_time - last_run) < seconds_from_interval(self.interval):
            self.helper.metric.state("idle")
            new_interval = seconds_from_interval(self.interval) - (
                current_time - last_run
            )
            self.helper.log_info(
                f"{self.helper.connect_name} connector will not run for {collector_name}, "
                f"next run in: {round(new_interval / 60 / 60, 2)} hours"
            )
            return

        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        now = datetime.fromtimestamp(current_time, UTC)
        friendly_name = f'{self.helper.connect_name} - {collector_name} run @ {now.strftime("%Y-%m-%d %H:%M:%S")}'
        work_id = self.helper.api.work.initiate_work(
            str(self.helper.connect_id), friendly_name
        )

        try:
            # Performing the collection of intelligence
            self.helper.log_debug(
                f"{self.helper.connect_name} connector is starting the collection of objects..."
            )
            self.helper.log_info(f"Running collector: {collector_name}")
            missed_entries, bundle_objects = collector.collect_intelligence(
                now, datetime.fromtimestamp(last_run, UTC), self.helper.connector_logger
            )
            if missed_entries > 0:
                self.helper.log_warning(
                    f"Collector {collector_name} missed {missed_entries} entries"
                )
            if len(bundle_objects) > 0:
                self.send_bundle(work_id, bundle_objects)

        except Exception as e:
            self.helper.log_error(str(e))

            # Store the current timestamp as a last run
        message = f"{self.helper.connect_name} connector successfully run for endpoint {collector_name}, storing last_run as {current_time}"
        self.helper.log_info(message)

        self.helper.log_debug(
            f"Grabbing current state for {collector_name} and update it with last_run: {now.isoformat()}"
        )
        current_state = self.helper.get_state()
        if current_state:
            current_state[collector_name] = {"last_run": current_time}
        else:
            current_state = {collector_name: {"last_run": current_time}}
        self.helper.set_state(current_state)

        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(
            f"Last_run for {collector_name} stored, next run in: {round(seconds_from_interval(self.interval) / 60 / 60, 2)} hours"
        )

    def run(self) -> None:
        # Main procedure
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        while True:
            try:
                # Get the current timestamp and check
                current_time = int(time.time())
                current_state = self.helper.get_state()

                for collector_name, collector in self.collectors.items():
                    if (
                        current_state is not None
                        and "last_run" in current_state[collector_name]
                    ):
                        last_run = current_state[collector_name]["last_run"]
                        self.helper.log_info(
                            f"{self.helper.connect_name} connector last run for {collector_name}: "
                            f'{datetime.fromtimestamp(last_run, UTC).strftime("%Y-%m-%d %H:%M:%S")}'
                        )
                    else:
                        last_run = None
                        self.helper.log_info(
                            f"Collector has never run. Doing an initial pull of {self.first_run_interval}"
                        )

                    self.collect_intelligence_for_endpoint(
                        current_time, last_run, collector_name, collector
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


if __name__ == "__main__":
    try:
        connector = ZeroFoxConnector()
        print("connector created")
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
