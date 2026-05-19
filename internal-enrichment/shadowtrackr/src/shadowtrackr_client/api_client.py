import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class ShadowTrackrClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: str):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (HttpUrl): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper
        self.logger = helper.connector_logger

        self.base_url = base_url
        self.api_key = api_key
        # Define headers in session and update when needed
        self.session = requests.Session()

    def _request_data(self, api_url: str, params=None) -> requests.Response | None:
        """
        Internal method to handle API requests
        :return: Response object
        """
        try:
            response = self.session.get(api_url, params=params)

            self.logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.logger.error(error_msg, {"url_path": api_url, "error": str(err)})
            return None

    def get_ip_info(self, ip: str, labels: list[str] | None) -> dict | None:
        """
        Get the information about an IP address from ShadowTrackr.

        :param ip: The IP address to get the information about
        :param labels: Optional labels to filter the information
        :return: A dictionary with the information about the IP address
        """
        try:
            params = {"api_key": self.api_key, "ip": ip, "labels": labels or ""}
            response = self._request_data(f"{self.base_url}/ip_info", params=params)
            return response.json() if response else None

        except Exception as err:
            self.logger.error("[API] Error while fetching IP info", {"error": str(err)})
            return None
