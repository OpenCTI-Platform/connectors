import json
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from connector.settings import ConnectorSettings

CONFIG_SECTORS_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json"
CONFIG_GEOGRAPHY_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json"
CONFIG_COMPANIES_FILE_URL = "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json"


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


class OpenCTI:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.config_interval = self.config.config.interval
        self.remove_creator = self.config.config.remove_creator
        urls = [
            self.config.config.sectors_file_url,
            self.config.config.geography_file_url,
            self.config.config.companies_file_url,
        ]
        self.urls = list(filter(lambda url: url is not False, urls))
        self.interval = days_to_seconds(self.config_interval)

    def retrieve_data(self, url: str) -> dict:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        dict
            A bundle in dict
        """
        try:
            return json.loads(
                urllib.request.urlopen(url, context=ssl.create_default_context())
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

    def creator_removal(self, bundle: dict) -> dict:
        for obj in bundle["objects"]:
            if "created_by_ref" in obj:
                del obj["created_by_ref"]
        return bundle

    def process_data(self):
        try:
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            if last_run is None or timestamp - last_run > self.interval:
                now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                friendly_name = "OpenCTI datasets run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                for url in self.urls:
                    try:
                        data = self.retrieve_data(url)
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
                    + str(round(self.interval / 60 / 60 / 24, 2))
                    + " days"
                )
            else:
                new_interval = self.interval - (timestamp - last_run)
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
                update=True,
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
