import json
import os
import ssl
import sys
import time
import urllib.request
from datetime import datetime
from typing import Optional

import certifi
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class OpenCTI:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.opencti_sectors_file_url = get_config_variable(
            "CONFIG_SECTORS_FILE_URL", ["config", "sectors_file_url"], config
        )
        self.opencti_geography_file_url = get_config_variable(
            "CONFIG_GEOGRAPHY_FILE_URL", ["config", "geography_file_url"], config
        )
        self.opencti_interval = get_config_variable(
            "CONFIG_INTERVAL", ["config", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def get_interval(self):
        return int(self.opencti_interval) * 60 * 60 * 24

    def retrieve_data(self, url: str) -> Optional[str]:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        str
            A string with the content or None in case of failure.
        """
        try:
            return (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(cafile=certifi.where()),
                )
                .read()
                .decode("utf-8")
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
        return None

    # Add confidence to every object in a bundle
    def add_confidence_to_bundle_objects(self, serialized_bundle: str) -> str:
        # the list of object types for which the confidence has to be added
        # (skip marking-definition, identity, external-reference-as-report)
        object_types_with_confidence = ["identity", "location", "relationship"]
        stix_bundle = json.loads(serialized_bundle)
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type in object_types_with_confidence:
                # self.helper.log_info(f"Adding confidence to {object_type} object")
                obj["confidence"] = int(self.helper.connect_confidence_level)
        return json.dumps(stix_bundle)

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run)
                > ((int(self.opencti_interval) - 1) * 60 * 60 * 24)
            ):
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "OpenCTI datasets run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                try:
                    sectors_data = self.retrieve_data(self.opencti_sectors_file_url)
                    sectors_data_with_confidence = (
                        self.add_confidence_to_bundle_objects(sectors_data)
                    )
                    self.send_bundle(work_id, sectors_data_with_confidence)
                except Exception as e:
                    self.helper.log_error(str(e))
                try:
                    geography_data = self.retrieve_data(self.opencti_geography_file_url)
                    geography_data_with_confidence = (
                        self.add_confidence_to_bundle_objects(geography_data)
                    )
                    self.send_bundle(work_id, geography_data_with_confidence)
                except Exception as e:
                    self.helper.log_error(str(e))
                # Store the current timestamp as a last run
                message = "Connector successfully run, storing last_run as " + str(
                    timestamp
                )
                self.helper.log_info(message)
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def run(self):
        self.helper.log_info("Fetching OpenCTI datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        openCTIConnector = OpenCTI()
        openCTIConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
