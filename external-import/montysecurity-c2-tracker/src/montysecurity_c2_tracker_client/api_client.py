import re

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class MontysecurityC2TrackerClient:
    def __init__(self, helper: OpenCTIConnectorHelper):
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

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_malwares(self, params=None) -> dict:
        try:
            self.helper.connector_logger.info("Get Malware Entities")

            # TODO: move to conf
            malware_list_url = (
                "https://github.com/montysecurity/C2-Tracker/tree/main/data"
            )
            # self.helper.connector_logger.info(self.helper.config.get(malware_list_url))
            response = self._request_data(malware_list_url, params=params)
            self.helper.connector_logger.info(
                "Status code from github.com: ", response.status_code
            )
            malware_list = list(
                set(re.findall('"[\w|\s|\d|\.]+IPs\.txt"', response.text))
            )

            return malware_list

        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_ips(self, malware_name: str, params=None) -> list:
        try:
            self.helper.connector_logger.info("Get Malware IPs")

            # TODO: move to conf
            malwareIPsBaseUrl = (
                "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/"
            )

            url = str(malwareIPsBaseUrl + str(malware_name).replace(" ", "%20"))
            response = self._request_data(url, params=params)
            ips = str(response.text).split("\n")
            ips.pop()

            return ips
            # TODO: ask if better exception filtering is needed
        except Exception as err:
            self.helper.connector_logger.error(err)
