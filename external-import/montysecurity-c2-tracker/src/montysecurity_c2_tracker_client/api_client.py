import re
from typing import Any
from urllib.parse import quote, urljoin

import requests
from connector.settings import MontysecurityC2TrackerConfig
from pycti import OpenCTIConnectorHelper
from requests.exceptions import RequestException


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

    def get_malware_list(self, params=None) -> list[Any] | None:
        try:
            self.helper.connector_logger.info("Get Malware Entities")
            malware_list_url = self.config.malware_list_url.encoded_string()
            response = self._request_data(malware_list_url, params=params)
            self.helper.connector_logger.info(
                "Status code from github.com: ", response.status_code
            )
            malware_list = list(set(re.findall("[\w\s\d.]+IPs\.txt", response.text)))

            return malware_list

        except RequestException as err:
            self.helper.connector_logger.error(
                f"Failed malware list: {err}", exc_info=True  # Includes full traceback
            )
            return []

    def get_ips(self, malware_name: str, params=None) -> list:
        try:
            self.helper.connector_logger.info("Get Malware IPs")

            malware_ips_base_url = self.config.malware_ips_base_url.encoded_string()

            url = urljoin(str(malware_ips_base_url), quote(malware_name))
            response = self._request_data(url, params=params)
            ips = [
                ip for ip in response.text.strip().split("\n") if ip
            ]  # Cleanup the list

            return ips
        except RequestException as err:
            self.helper.connector_logger.error(
                f"Failed malware list: {err}", exc_info=True  # Includes full traceback
            )
            return []
