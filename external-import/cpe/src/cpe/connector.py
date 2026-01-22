import math
import sys
import time
from datetime import datetime
from uuid import uuid4

import langcodes
import requests
import stix2
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .settings import ConnectorSettings

APP_VERSION = "1.0.0"


class CPEConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initializes the CPE connector
        """
        self.config = config
        self.helper = helper
        self.base_url = self.config.cpe.base_url
        self.api_key = self.config.cpe.api_key.get_secret_value()

    def _get_request_params(self, api_url) -> dict:
        """
        Collects the request parameters from the NIST API

        Args:
            api_url (str): The URL to use to collect the request parameters

        Returns:
            dict: The request parameters
        """
        self.helper.log_info("Retrieving the API request parameters...")
        session = requests.Session()
        headers = {
            "apiKey": self.api_key,
            "User-Agent": f"OpenCTI-cpe-connector/{APP_VERSION}",
        }
        retry_strategy = Retry(
            total=4, backoff_factor=6, status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        response = session.get(str(api_url), headers=headers)
        parameters = {}
        if response.status_code == 200:
            resultsPerPage = response.json().get("resultsPerPage")
            startIndex = response.json().get("startIndex")
            totalResults = response.json().get("totalResults")
            parameters = dict(
                resultsPerPage=resultsPerPage,
                startIndex=startIndex,
                totalResults=totalResults,
            )
            self.helper.log_info("API request parameters retrieved!")
            return parameters
        else:
            self.helper.log_error(
                f"Error retrieving the API request parameters from the NIST API: {response.status_code}"
            )
            return parameters

    def _get_cpe_list(self, api_url) -> list:
        """
        Collects the CPE list from the NIST API

        Args:
            api_url (str): The URL to use to collect the CPE list

        Returns:
            list: The CPE list
        """
        self.helper.log_debug(api_url)
        session = requests.Session()
        headers = {
            "apiKey": self.api_key,
            "User-Agent": f"OpenCTI-cpe-connector/{APP_VERSION}",
        }
        retry_strategy = Retry(
            total=4, backoff_factor=6, status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        response = session.get(api_url, headers=headers)
        if response.status_code == 200:
            self.helper.log_info(
                str(response.json().get("resultsPerPage")) + " CPEs retrieved!"
            )
            return response.json()
        else:
            self.helper.log_error(
                f"Error retrieving the CPE list from the NIST API: {response.status_code}"
            )
            return []

    def _get_date_iso(self, timestamp: int) -> str:
        """
        Converts a timestamp to a date in ISO format

        Args:
            timestamp (int): The timestamp to convert

        Returns:
            str: The date formatted as "AAAA-MM-JJTHH:MM:SS.ss"
        """
        return datetime.utcfromtimestamp(timestamp).isoformat()

    def _get_id(self, type: str) -> str:
        """
        Generates a unique ID for a STIX2 object

        Args:
            type (str): The type of the object to generate an ID for

        Returns:
            str: A unique ID for the STIX object
        """
        return f"{type}--{str(uuid4())}"

    def _get_api_url(self, start_index, start_date, end_date) -> str:
        """
        Returns the API URL to use for the connector

        Args:
            startIndex (int): The index to start from
            start_date (str): The start date to use
            end_date (str): The end date to use

        Returns:
            str: The API URL to use
        """
        if start_date is None and end_date is None:
            return f"{self.base_url}?startIndex={start_index}"
        else:
            return f"{self.base_url}?startIndex={start_index}&lastModStartDate={start_date}&lastModEndDate={end_date}"

    def _get_cpe_infos(self, cpe: str) -> dict:
        """
        Returns the vendor, name, version and language of a CPE

        Args:
            cpe (str): The CPE to get the informations from

        Returns:
            dict: A dictionary containing the vendor, name, version and language of the CPE
        """
        if cpe.split(":")[2] == "h":
            is_hardware = True
        else:
            is_hardware = False
        if cpe.split(":")[3] == "*":
            vendor = ""
        else:
            vendor = cpe.split(":")[3]
        if cpe.split(":")[4] == "*":
            name = ""
        else:
            name = cpe.split(":")[4].replace("_", " ")
        if cpe.split(":")[5] == "*":
            version = ""
        else:
            version = cpe.split(":")[5]
        if cpe.split(":")[8] == "*":
            language = ""
        else:
            try:
                language = langcodes.standardize_tag(cpe.split(":")[8], "ietf")
            except Exception as e:
                language = ""
                self.helper.log_error(f"Error while getting language. {str(e)}")
        return {
            "is_hardware": is_hardware,
            "vendor": vendor,
            "name": name,
            "version": version,
            "language": language,
        }

    def _json_to_stix(self, json_objects: list) -> list:
        """
        Converts a JSON object to a STIX2 object

        Args:
            self
            json_objects (list): The JSON objects to convert

        Returns:
            list: A list of STIX2 objects
        """
        self.helper.log_info("Converting JSON objects to STIX2 objects...")
        nb_results = json_objects["resultsPerPage"]
        stix_objects = []
        for i in range(nb_results):
            cpe_infos = self._get_cpe_infos(
                json_objects["products"][i]["cpe"]["cpeName"]
            )
            if (
                json_objects["products"][i]["cpe"]["deprecated"] is False
                and cpe_infos["is_hardware"] is False
            ):
                self.helper.log_debug(
                    f"Creating a software for the CPE: {json_objects['products'][i]['cpe']['cpeName']}"
                )
                software = stix2.Software(
                    type="software",
                    spec_version="2.1",
                    id=self._get_id("software"),
                    name=self._get_cpe_title(json_objects["products"][i]["cpe"]),
                    cpe=json_objects["products"][i]["cpe"]["cpeName"],
                    languages=cpe_infos["language"],
                    vendor=cpe_infos["vendor"],
                    version=cpe_infos["version"],
                )
                stix_objects.append(software)
        self.helper.log_info(f"{len(stix_objects)} STIX2 objects have been created!")
        return stix_objects

    def _get_cpe_title(self, cpe: dict) -> str:
        """
        Extracts the title from the cpe.

        Args:
            self
            cpe (dict): The cpe where the title is extracted

        Returns:
            str: The title of the cpe.
        """
        cpe_title = ""
        for title in cpe["titles"]:
            if title["lang"] == "en":
                cpe_title = title["title"]
        if cpe_title == "":
            cpe_title = self._get_cpe_infos(cpe["cpeName"])["name"]
        return cpe_title

    def _import_all(self, work_id) -> None:
        """
        Imports all the CPEs from the NIST API

        Args:
            work_id (str): The work ID to use
        """
        self.helper.log_info(
            f"{self.helper.connect_name} connector is starting the collection of all CPEs..."
        )
        api_url = self._get_api_url(0, None, None)
        parameters = self._get_request_params(api_url)
        if parameters["totalResults"] == 0:
            self.helper.log_info("No CPEs to import!")
            return
        total_request = math.ceil(
            parameters["totalResults"] / parameters["resultsPerPage"]
        )
        stix_objects = []
        for i in range(total_request):
            api_url = self._get_api_url(i * parameters["resultsPerPage"], None, None)
            json_objects = self._get_cpe_list(api_url)
            stix_objects = self._json_to_stix(json_objects)
            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
            self.helper.log_info(
                f"Sending {len(stix_objects)} STIX objects to OpenCTI..."
            )
            self.helper.send_stix2_bundle(bundle, update=False, work_id=work_id)
            time.sleep(6)

    def _import_date(self, work_id) -> None:
        """
        Imports the CPEs from the NIST API based on a time difference between the last run and the current time

        Args:
            work_id (str): The work ID to use
        """
        self.helper.log_info(
            f"{self.helper.connect_name} connector is starting the collection of CPEs based on a time difference..."
        )
        last_run_date = self._get_date_iso(self.last_run)
        current_date = self._get_date_iso(self.current_run)
        api_url = self._get_api_url(0, last_run_date, current_date)
        parameters = self._get_request_params(api_url)
        if parameters["totalResults"] == 0:
            self.helper.log_info("No CPEs to import!")
            return
        total_request = math.ceil(
            parameters["totalResults"] / parameters["resultsPerPage"]
        )
        stix_objects = []
        for i in range(total_request):
            api_url = self._get_api_url(
                i * parameters["resultsPerPage"], last_run_date, current_date
            )
            json_objects = self._get_cpe_list(api_url)
            stix_objects = self._json_to_stix(json_objects)
            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
            self.helper.log_info(
                f"Sending {len(stix_objects)} STIX objects to OpenCTI..."
            )
            self.helper.send_stix2_bundle(bundle, update=False, work_id=work_id)
            time.sleep(6)

    def run(self) -> None:
        """
        Runs the CPE connector
        """
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        interval = self.config.connector.duration_period.seconds
        while True:
            try:
                self.current_run = int(time.time())
                current_state = self.helper.get_state()
                last_run = None
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                self.last_run = last_run
                if (
                    last_run is None
                    or self.current_run - last_run >= 120 * 24 * 60 * 60
                ):
                    if last_run is None:
                        self.helper.log_info(
                            f"{self.helper.connect_name} connector has never run"
                        )
                    else:
                        self.helper.log_info(
                            f"{self.helper.connect_name} connector has not run in more than 120 days"
                        )
                    self.helper.log_info(
                        f"{self.helper.connect_name} will run and collect all the CPEs!"
                    )
                    now = datetime.utcfromtimestamp(self.current_run)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        self._import_all(work_id)
                    except Exception as e:
                        self.helper.log_debug(str(e))
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(self.current_run)
                    )
                    self.helper.log_info(message)
                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {self.current_run}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = self.current_run
                    else:
                        current_state = {"last_run": self.current_run}
                    self.helper.set_state(current_state)
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(interval / 60 / 60, 2))
                        + " hours"
                    )
                elif self.current_run - last_run >= interval:
                    self.helper.log_info(
                        f"{self.helper.connect_name} will run and collect the CPEs based on a time difference!"
                    )
                    now = datetime.utcfromtimestamp(self.current_run)
                    friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        self._import_date(work_id)
                    except Exception as e:
                        self.helper.log_debug(str(e))
                    message = (
                        f"{self.helper.connect_name} connector successfully run, storing last_run as "
                        + str(self.current_run)
                    )
                    self.helper.log_info(message)
                    self.helper.log_debug(
                        f"Grabbing current state and update it with last_run: {self.current_run}"
                    )
                    current_state = self.helper.get_state()
                    if current_state:
                        current_state["last_run"] = self.current_run
                    else:
                        current_state = {"last_run": self.current_run}
                    self.helper.set_state(current_state)
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(interval / 60 / 60, 2))
                        + " hours"
                    )
                else:
                    new_interval = interval - (self.current_run - last_run)
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
                sys.exit(0)
            time.sleep(60)
