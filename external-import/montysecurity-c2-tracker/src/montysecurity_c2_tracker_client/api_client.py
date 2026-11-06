import re
from urllib.parse import quote, urljoin

import requests
from connector.settings import MontysecurityC2TrackerConfig
from pycti import OpenCTIConnectorHelper
from requests.exceptions import RequestException


class MontysecurityC2TrackerSourceError(Exception):
    """Raised when the malware list cannot be read from the configured source."""


class MontysecurityC2TrackerClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper, config: MontysecurityC2TrackerConfig
    ):
        """
        Initialize the client with necessary configuration.
        The connector helper is injected for logging and tracing.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params: dict | None = None):
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
            # Logged as a warning, message only: the caller decides whether the
            # failure fails the run (get_malware_list raises, and process_message
            # logs the error once) or skips one malware file (get_ips).
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.warning(
                error_msg, {"url_path": api_url, "error": str(err)}
            )
            return None

    def get_malware_list(self, params: dict | None = None) -> list[str]:
        """Fetch the list of malware from the external API.

        Raises:
            MontysecurityC2TrackerSourceError: the source cannot be reached or
                lists no malware file, so the run must not be reported as successful.
        """
        self.helper.connector_logger.info("Get Malware Entities")
        malware_list_url = self.config.malware_list_url.encoded_string()
        response = self._request_data(malware_list_url, params=params)
        if response is None:
            raise MontysecurityC2TrackerSourceError(
                f"Malware list source cannot be reached: {malware_list_url}"
            )
        self.helper.connector_logger.info(
            f"Status code from github.com: {response.status_code}"
        )

        malware_list = list(
            set(
                # Match filenames ending with "IPs.txt":
                # - start on a word boundary
                # - first token must start with a letter
                # - allow extra space-separated tokens (letters/digits + _, ., -)
                # - require a final " IPs.txt" suffix
                re.findall(
                    r"\b[A-Za-z][\w.-]*(?:\s+[A-Za-z0-9][\w.-]*)*\s+IPs\.txt\b",
                    response.text,
                )
            )
        )

        if not malware_list:
            raise MontysecurityC2TrackerSourceError(
                f"Malware list source lists no malware file: {malware_list_url}"
            )

        return malware_list

    def get_ips(self, malware_name: str, params: dict | None = None) -> list[str]:
        """Fetch the list of IPs associated with a malware from the external API."""
        try:
            self.helper.connector_logger.info("Get Malware IPs")

            malware_ips_base_url = self.config.malware_ips_base_url.encoded_string()

            url = urljoin(str(malware_ips_base_url), quote(malware_name))
            response = self._request_data(url, params=params)
            if response is None:
                return []

            return [
                ip for ip in response.text.strip().split("\n") if ip
            ]  # Cleanup the list

        except RequestException as err:
            self.helper.connector_logger.error(
                f"Failed malware list: {err}",
                exc_info=True,  # Includes full traceback
            )
            return []
