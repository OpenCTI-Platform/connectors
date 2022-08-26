# coding: utf-8

import gzip
import os
import shutil
import ssl
import sys
import time
import urllib.request
from datetime import datetime

import certifi
import yaml
from cvetostix2 import convert
from pycti import OpenCTIConnectorHelper, get_config_variable


class Cve:
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
        self.cve_import_history = get_config_variable(
            "CVE_IMPORT_HISTORY", ["cve", "import_history"], config, False
        )
        self.cve_nvd_data_feed = get_config_variable(
            "CVE_NVD_DATA_FEED", ["cve", "nvd_data_feed"], config
        )
        self.cve_history_data_feed = get_config_variable(
            "CVE_HISTORY_DATA_FEED",
            ["cve", "history_data_feed"],
            config,
        )
        self.cve_history_start_date = get_config_variable(
            "CVE_HISTORY_START_DATE", ["cve", "history_start_date"], config, True
        )
        self.cve_interval = get_config_variable(
            "CVE_INTERVAL", ["cve", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def get_interval(self):
        return int(self.cve_interval) * 60 * 60 * 24

    def delete_files(self):
        if os.path.exists("data.json"):
            os.remove("data.json")
        if os.path.exists("data.json.gz"):
            os.remove("data.json.gz")
        if os.path.exists("data-stix2.json"):
            os.remove("data-stix2.json")

    def convert_and_send(self, url, work_id):
        try:
            # Downloading json.gz file
            self.helper.log_info("Requesting the file " + url)
            response = urllib.request.urlopen(
                url, context=ssl.create_default_context(cafile=certifi.where())
            )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.json.gz", "wb"
            ) as file:
                file.write(image)
            # Unzipping the file
            self.helper.log_info("Unzipping the file")
            with gzip.open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.json.gz", "rb"
            ) as f_in:
                with open("data.json", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            # Converting the file to stix2
            self.helper.log_info("Converting the file")
            convert("data.json", "data-stix2.json")
            with open("data-stix2.json") as stix_json:
                contents = stix_json.read()
                self.helper.send_stix2_bundle(
                    contents,
                    entities_types=self.helper.connect_scope,
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            # Remove files
            self.delete_files()
        except Exception as e:
            self.delete_files()
            self.helper.log_error(str(e))
            time.sleep(60)

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
                (timestamp - last_run) > ((int(self.cve_interval) - 1) * 60 * 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "CVE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.convert_and_send(self.cve_nvd_data_feed, work_id)
                # If import history and never run
                if last_run is None and self.cve_import_history:
                    now = datetime.now()
                    years = list(range(self.cve_history_start_date, now.year + 1))
                    for year in years:
                        self.convert_and_send(
                            f"{self.cve_history_data_feed}nvdcve-1.1-{year}.json.gz",
                            work_id,
                        )

                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
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

    def run(self):
        self.helper.log_info("Fetching CVE knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)


if __name__ == "__main__":
    try:
        cveConnector = Cve()
        cveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
