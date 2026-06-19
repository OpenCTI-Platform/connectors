import json

import requests
from pycti import OpenCTIConnectorHelper


class WorkshopConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, sample_file_path: str):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (str): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper

        self.sample_file_path = sample_file_path
        self.domain_path = "/domains_sample.json"
        self.ip_addresses_path = "/ip_addresses_sample.json"
        self.vulnerabilities_path = "/vulnerabilities_sample.json"

    def _from_json(self, sample_file_path: str) -> dict:
        with open(sample_file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _request_data(self, sample_file_path: str):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self._from_json(sample_file_path)
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {sample_file_path}, "error": {str(err)}}
            )
            return None

    def get_domain_entities(self) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            response = self._request_data(self.sample_file_path + self.domain_path)

            return response
            # ===========================
            # === Add your code above ===
            # ===========================

            # raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_ip_entities(self) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            response = self._request_data(
                self.sample_file_path + self.ip_addresses_path
            )

            return response
            # ===========================
            # === Add your code above ===
            # ===========================

            # raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_vulnerability_entities(self) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            response = self._request_data(
                self.sample_file_path + self.vulnerabilities_path
            )

            return response
            # ===========================
            # === Add your code above ===
            # ===========================

            # raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
