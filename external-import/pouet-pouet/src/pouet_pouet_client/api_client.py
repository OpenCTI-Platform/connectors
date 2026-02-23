from datetime import datetime
from typing import Generator

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class PouetPouetClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: str):
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

        self.base_url = base_url
        # Define headers in session and update when needed
        headers = {"Bearer": api_key}
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

    def get_reports(self, since: datetime | None = None) -> Generator[dict, None, None]:
        """
        If since is None, retrieve all reports from the API.
        :param since: Optional parameter to filter reports based on a timestamp
        :return: A generator of dicts representing the complete collection of reports from the API
        """
        _ = since

        yield {"id": 123, "name": "Example Entity"}
        yield {"id": 456, "name": "Another Example Entity"}
