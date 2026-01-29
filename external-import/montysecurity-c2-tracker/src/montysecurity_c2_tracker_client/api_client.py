import re
from typing import Any
from urllib.parse import urljoin, quote

import requests
from connector.settings import MontysecurityC2TrackerConfig
from pycti import OpenCTIConnectorHelper

class MontysecurityC2TrackerClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper, config: MontysecurityC2TrackerConfig
    ):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.config = config

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

    def get_malwares(self, params=None) -> list[Any] | None:
        try:
            self.helper.connector_logger.info("Get Malware Entities")
            malware_list_url = (
                self.config.malware_list_url.encoded_string()
            )
            response = self._request_data(malware_list_url, params=params)
            self.helper.connector_logger.info(
                "Status code from github.com: ", response.status_code
            )
            malware_list = list(
                set(re.findall('[\w\s\d.]+IPs\.txt', response.text))
            )

            return malware_list

        except Exception as err:
            self.helper.connector_logger.error(err)

    def get_ips(self, malware_name: str, params=None) -> list:
        try:
            self.helper.connector_logger.info("Get Malware IPs")

            malware_ips_base_url = (
                self.config.malware_ips_base_url.encoded_string()
            )

            url = urljoin(str(malware_ips_base_url), quote(malware_name))
            response = self._request_data(url, params=params)
            ips = str(response.text).split("\n")
            ips.pop()

            return ips
            # TODO: ask if better exception filtering is needed
        except Exception as err:
            self.helper.connector_logger.error(err)
