"""Cyber Monitor connector module."""
import base64
import mimetypes
import os
import ssl
import sys
import time
import urllib
from datetime import date, datetime
from typing import Optional

import requests
import stix2
import yaml
from dateutil import parser
from github import Github
from pycti import OpenCTIConnectorHelper, Report, get_config_variable
from requests import RequestException


class CyberMonitor:
    """Cyber Monitor connector."""

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
        self.cyber_monitor_github_token = get_config_variable(
            "CYBER_MONITOR_GITHUB_TOKEN",
            ["cyber_monitor", "github_token"],
            config,
            False,
            None,
        )
        if (
            self.cyber_monitor_github_token is not None
            and len(self.cyber_monitor_github_token) == 0
        ):
            self.cyber_monitor_github_token = None
        self.cyber_monitor_from_year = get_config_variable(
            "CYBER_MONITOR_FROM_YEAR", ["cyber_monitor", "from_year"], config, True
        )
        self.cyber_monitor_interval = get_config_variable(
            "CYBER_MONITOR_INTERVAL", ["cyber_monitor", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
        )

        self.dummy_organization = self.helper.api.identity.create(
            type="Organization",
            name="DUMMY",
            description="Dummy organization which can be used in various unknown contexts.",
        )

    def get_interval(self):
        return int(self.cyber_monitor_interval) * 60 * 60 * 24

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
                    context=ssl.create_default_context(),
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

    def _send_request(self, url, params=None, binary=False):
        """
        Sends the HTTP request and handle the errors
        """
        try:
            res = requests.get(url, params=params)
            res.raise_for_status()
            if binary:
                return res.content
            return res.json()
        except RequestException as ex:
            if ex.response:
                error = f"Request failed with status: {ex.response.status_code}"
                self.helper.log_error(error)
            else:
                self.helper.log_error(str(ex))
            return None

    def _import_year(self, year, work_id):
        g = Github(self.cyber_monitor_github_token)
        repo = g.get_repo("CyberMonitor/APT_CyberCriminal_Campagin_Collections")
        contents = repo.get_contents("")
        for content_file in contents:
            if content_file.path == str(year):
                self.helper.log_info("Importing year " + str(year))
                year_contents = repo.get_contents(content_file.path)
                for report_dir in year_contents:
                    # Sanitize
                    report_date = report_dir.name[0:10].replace(".", "-")

                    # Force report date to first month and/or first day if it is lacking
                    # either field
                    if report_date[5:7] == "00" or not report_date[5:7].isdigit():
                        report_date = report_date[0:5] + "01" + report_date[7:]

                    if report_date[8:10] == "00" or not report_date[8:10].isdigit():
                        report_date = report_date[0:8] + "01"

                    # Overwrite sanitized report_date with dateparser output from it
                    report_date = parser.parse(report_date)
                    report_name = (
                        report_dir.name[11:].replace("_", " ").replace("-", " ")
                    )
                    self.helper.log_info(
                        "Import report (date="
                        + str(report_date)
                        + ", name="
                        + report_name
                        + ")"
                    )
                    external_reference = stix2.ExternalReference(
                        source_name="Cyber Campaign Collections",
                        url="https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/tree/master/"
                        + report_dir.path,
                    )
                    files_content = repo.get_contents(report_dir.path)
                    files = []
                    for file in files_content:
                        data = self._send_request(file.download_url, binary=True)
                        if data:
                            files.append(
                                {
                                    "name": file.name,
                                    "data": base64.b64encode(data).decode("utf-8"),
                                    "mime_type": mimetypes.guess_type(
                                        file.download_url
                                    )[0],
                                }
                            )
                    report = stix2.Report(
                        id=Report.generate_id(report_name, report_date),
                        name=report_name,
                        published=report_date,
                        external_references=[external_reference],
                        object_refs=[self.dummy_organization["standard_id"]],
                        allow_custom=True,
                        custom_properties={"x_opencti_files": files},
                    )
                    self.send_bundle(
                        work_id,
                        stix2.Bundle(objects=[report], allow_custom=True).serialize(),
                    )

    def import_history(self, work_id):
        current_year = date.today().year
        years_range = current_year - self.cyber_monitor_from_year
        for x in range(years_range):
            year = self.cyber_monitor_from_year + x
            self._import_year(year, work_id)

    def import_current_year(self, work_id):
        self._import_year(date.today().year, work_id)

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
                > ((int(self.cyber_monitor_interval) - 1) * 60 * 60 * 24)
            ):
                self.helper.log_info("Connector will run!")

                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "Cyber Monitor run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                if last_run is None:
                    # Import history data
                    self.import_history(work_id)

                # Import current year
                self.import_current_year(work_id)

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

    def run(self):
        self.helper.log_info("Fetching Cyber Monitor datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

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


if __name__ == "__main__":
    try:
        cyberMonitorConnector = CyberMonitor()
        cyberMonitorConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
