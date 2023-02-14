import json
import ssl
import sys
import time
import urllib.request
from datetime import datetime
from typing import Optional

import certifi
from pycti import OpenCTIConnectorHelper, get_config_variable

CONFIG_SECTORS_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json"
CONFIG_GEOGRAPHY_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json"
# CONFIG_COMPANIES_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json"


class OpenCTI:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA", []
        )
        self.interval = get_config_variable("CONFIG_INTERVAL", [], isNumber=True)
        self.remove_creator = get_config_variable("CONFIG_REMOVE_CREATOR", [])

        urls = [
            get_config_variable(
                "CONFIG_SECTORS_FILE_URL", [""], default=CONFIG_SECTORS_FILE_URL
            ),
            get_config_variable(
                "CONFIG_GEOGRAPHY_FILE_URL",
                [""],
                default=CONFIG_GEOGRAPHY_FILE_URL,
            ),
            # get_config_variable(
            #     "CONFIG_COMPANIES_FILE_URL", [""], default=CONFIG_COMPANIES_FILE_URL
            # )
        ]

        self.urls = list(filter(lambda url: url is not False, urls))

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

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
            return json.loads(
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

    def add_confidence(self, bundle: dict) -> dict:
        confidence = int(self.helper.connect_confidence_level)
        types = ["identity", "location", "relationship"]

        for obj in bundle["objects"]:
            if obj["type"] in types:
                obj["confidence"] = confidence

        return bundle

    def creator_removal(self, bundle: dict) -> dict:
        for obj in bundle["objects"]:
            if "created_by_ref" in obj:
                del obj["created_by_ref"]
        return bundle

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
                (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
            ):
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "OpenCTI datasets run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                for url in self.urls:
                    try:
                        data = self.retrieve_data(url)
                        data = self.add_confidence(data)
                        if self.remove_creator:
                            data = self.creator_removal(data)
                        self.send_bundle(work_id, data)
                    except Exception as e:
                        self.helper.log_error(str(e))

                message = f"Connector successfully run, storing last_run as {timestamp}"
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

    def send_bundle(self, work_id: str, data: dict) -> None:
        try:
            self.helper.send_stix2_bundle(
                json.dumps(data),
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
