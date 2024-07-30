import base64
import json
import os
import sys
import time
import traceback
from datetime import datetime, timedelta

import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable


class ReportHub:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.safe_load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        self._downloader_config = {
            "base_url": self.get_config(
                "base_url", config, "https://api.rstcloud.net/v1"
            ),
            "api_key": self.get_config("api_key", config, None),
            "connection_timeout": int(
                self.get_config("connection_timeout", config, 30)
            ),
            "read_timeout": int(self.get_config("read_timeout", config, 60)),
            "retry_delay": int(self.get_config("retry_delay", config, 30)),
            "retry_attempts": int(self.get_config("retry_attempts", config, 5)),
            "import_start_date": str(
                self.get_config(
                    "import_start_date",
                    config,
                    (datetime.today() - timedelta(days=7)).strftime("%Y%m%d"),
                )
            ),
            "fetch_interval": int(self.get_config("fetch_interval", config, 300)),
            "language": str(self.get_config("language", config, "eng")),
        }
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    @staticmethod
    def get_config(name: str, config, default=None):
        env_name = "RST_REPORT_HUB_{}".format(name.upper())
        # usually this connector gets its config from variables
        # but if these are not defined, then it
        # reads 'rst-report-hub' property in the file config.yml
        result = get_config_variable(env_name, ["rst-report-hub", name], config)
        return result or default

    def _combine_report_and_send(self, stix_bundle, x_opencti_file, report_id):
        # Parse the STIX bundle
        parsed_bundle = json.loads(stix_bundle)
        stix_bundle_main = []
        for entry in parsed_bundle.get("objects", []):
            stix_bundle_main.append(entry)
            # attach PDFs only to the Report object
            if x_opencti_file and entry.get("type", "") == "report":
                entry["x_opencti_files"] = [x_opencti_file]

        message = "Importing " + report_id.replace("_", " ")
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, message)
        self._send_stix_data(work_id, stix_bundle_main)
        message = f"Processed {len(stix_bundle_main)} objects from RST Report Hub for {report_id}"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info(message)
        return True

    def _convert_and_attach_pdfs(self, headers, reports, lang):
        for report in reports:
            report_id = report.get("id")

            params_stix = {"id": report_id, "format": "stix", "lang": lang}
            params_pdf = {"id": report_id, "format": "pdf"}
            try:
                self.helper.log_debug(f"Fetching STIX for {report_id}")
                response = requests.get(
                    self._downloader_config["base_url"] + "/reports",
                    headers=headers,
                    params=params_stix,
                    timeout=(
                        self._downloader_config["connection_timeout"],
                        self._downloader_config["read_timeout"],
                    ),
                )
                response.raise_for_status()
                stix_report = response.content
            except requests.exceptions.RequestException:
                self.helper.log_error(f"Could not fetch STIX for {report_id}")
                continue

            if stix_report:
                try:
                    self.helper.log_debug(f"Fetching PDF for {report_id}")
                    response = requests.get(
                        self._downloader_config["base_url"] + "/reports",
                        headers=headers,
                        params=params_pdf,
                        timeout=(
                            self._downloader_config["connection_timeout"],
                            self._downloader_config["read_timeout"],
                        ),
                    )
                    response.raise_for_status()

                    if response.status_code == 200:
                        pdf_report = response.content
                        file_pdf = {
                            "name": f"{report_id}.pdf",
                            "mime_type": "application/pdf",
                            "data": base64.b64encode(pdf_report).decode("utf-8"),
                        }
                        self._combine_report_and_send(stix_report, file_pdf, report_id)
                except requests.exceptions.RequestException as ex:
                    self.helper.log_error(
                        f"Failed to download and save entry {report_id} as PDF. {ex}"
                    )
                    self._combine_report_and_send(stix_report, {}, "")
        return True

    def _fetch_stix_reports(self, current_state):
        # to use as string
        import_date = current_state["import_date"]
        # to compare dates
        import_date_parsed = parse(import_date)
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._downloader_config["api_key"],
        }
        params = {
            "date": import_date,
            "lang": self._downloader_config["language"],
        }
        retry_attempts = self._downloader_config["retry_attempts"]
        retry_delay = self._downloader_config["retry_delay"]
        # import_date is not always today
        today = parse(datetime.now().strftime("%Y%m%d"))
        nextday = (import_date_parsed + timedelta(days=1)).strftime("%Y%m%d")

        for attempt in range(retry_attempts):
            try:
                response = requests.get(
                    self._downloader_config["base_url"] + "/reports",
                    headers=headers,
                    params=params,
                    timeout=(
                        self._downloader_config["connection_timeout"],
                        self._downloader_config["read_timeout"],
                    ),
                )
                response.raise_for_status()

                if response.status_code == 200:
                    reports = response.json()
                    # if the number of reports available changed,
                    # keep downloading "today"
                    if import_date_parsed == today and current_state[
                        "report_count"
                    ] >= len(reports):
                        self.helper.log_info(
                            f"Skipping as all reports for the current day {today} have been downloaded"
                        )
                        return True
                    else:
                        # if it is a day in the past downloaded,
                        # then go to next day until today
                        if import_date_parsed < today:
                            # next time start downloading the next day
                            # and reset the counter
                            self.helper.set_state(
                                {
                                    "import_date": nextday,
                                    "report_count": 0,
                                }
                            )
                        else:
                            # keep waiting for reports for a given day and
                            # keep the counter to skip re-fetching the same
                            # reports if no new reports appeared
                            self.helper.set_state(
                                {
                                    "import_date": import_date,
                                    "report_count": len(reports),
                                }
                            )
                        return self._convert_and_attach_pdfs(
                            headers,
                            response.json(),
                            self._downloader_config["language"],
                        )

            except requests.exceptions.RequestException:
                if response.status_code == 404:
                    # no reports for a given day found,
                    # iterate day by day until today
                    if import_date_parsed < today:
                        # next time start downloading the next day
                        # and reset the counter
                        self.helper.set_state(
                            {
                                "import_date": nextday,
                                "report_count": 0,
                            }
                        )
                    else:
                        # keep waiting for reports
                        # for a given day until tomorrow
                        self.helper.set_state(
                            {
                                "import_date": import_date,
                                "report_count": 0,
                            }
                        )
                    self.helper.log_info(
                        f"No reports found for a given date: {import_date}"
                    )
                    return False
                else:
                    self.helper.log_info(f"Failed to fetch reports: {import_date}")
                if attempt < retry_attempts - 1:
                    self.helper.log_info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.helper.log_info(
                        f"Failed to fetch reports {import_date} after {retry_attempts} attempts"
                    )
                    return False

        self.helper.log_info("Failed to fetch and save data.")
        return True

    def _fetch_and_process_data(self):
        # get the state and check if it is not set
        current_state = self.helper.get_state()
        if current_state is None:
            # first run or state was reset
            self.helper.set_state(
                {
                    "import_date": self._downloader_config["import_start_date"],
                    "report_count": 0,
                }
            )
            current_state = self.helper.get_state()
        else:
            # if a part of the state is not present,
            # the values should fail back to defaults
            if "report_count" not in current_state:
                current_state["report_count"] = 0
            if "import_date" not in current_state:
                current_state["import_date"] = self._downloader_config[
                    "import_start_date"
                ]
        # fetch reports for the import date specified in the state
        self._fetch_stix_reports(current_state)

    def _send_stix_data(self, work_id, report_bundle):
        try:
            bundle = stix2.v21.Bundle(objects=report_bundle, allow_custom=True)
            self.helper.send_stix2_bundle(
                bundle=bundle.serialize(),
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending STIX bundle: {e}")

    def run(self):
        self.helper.log_info("Starting RST Report Hub connector")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self._fetch_and_process_data()
            self.helper.force_ping()
        else:
            while True:
                self._fetch_and_process_data()
                time.sleep(self._downloader_config["fetch_interval"])


if __name__ == "__main__":
    try:
        connector = ReportHub()
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
