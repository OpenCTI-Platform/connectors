from typing import Any, Dict

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class CriminalIpClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        token: str,
    ):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            token (str): The API token to authenticate the connector to the external API.
        """
        self.helper = helper

        self.base_url = "https://api.criminalip.io"
        # Define headers in session and update when needed
        self.headers = {"x-api-key": token}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request_data(
        self, type_request: str, api_url: HttpUrl, params: Dict
    ) -> requests.Response:
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            if type_request == "GET":
                response = self.session.get(api_url, params=params, timeout=20)
                log_msg = "[CLIENT API] HTTP GET Request to endpoint"
            if type_request == "POST":
                response = self.session.post(api_url, data=params, timeout=20)
                log_msg = "[CLIENT API] HTTP POST Request to endpoint"

            self.helper.connector_logger.info(log_msg, {"url_path": api_url})

            response.raise_for_status()

            # Manage custom error from API
            response_json = response.json()
            status_reponse = response_json.get("status")
            match status_reponse:
                case "400":
                    self.helper.connector_logger.error(
                        "[CLIENT API] Invalid URL.", response_json
                    )
                    raise
                case "403":
                    self.helper.connector_logger.error(
                        "[CLIENT API] Free Membership users can view a total of 100 data queries.",
                        response_json,
                    )
                    raise
                case "412":
                    self.helper.connector_logger.error(
                        "[CLIENT API] Missing parameter.", response_json
                    )
                    raise
                case "420":
                    self.helper.connector_logger.error(
                        "[CLIENT API] Invalid parameter.", response_json
                    )
                    raise
                case "500":
                    self.helper.connector_logger.error(
                        "[CLIENT API] An error occured on the server.",
                        response_json,
                    )
                    raise
            return response

        except requests.exceptions.HTTPError as err:
            if response.status_code == 401:
                msg = "[CLIENT API] Permissions Error, Criminal IP returned a 401, please check your API key"
            elif response.status_code == 404:
                msg = (
                    "[CLIENT API] File not found on Criminal IP, no enrichment possible"
                )
            else:
                msg = "[CLIENT API] Http error"
            self.helper.connector_logger.error(msg, {"error": err})
            raise
        except requests.exceptions.ConnectionError as err:
            self.helper.connector_logger.error(
                "[CLIENT API] Error connecting", {"error": err}
            )
            raise
        except requests.exceptions.Timeout as err:
            self.helper.connector_logger.error(
                "[CLIENT API] Timeout error", {"error": err}
            )
            raise
        except requests.exceptions.RequestException as err:
            self.helper.connector_logger.error(
                "[CLIENT API] Something else happened", {"error": err}
            )
            raise
        except Exception as err:
            self.helper.connector_logger.error(
                "[CLIENT API] Unknown error", {"error": err}
            )
            raise

    def get_data(self, endpoint: str, params: Dict[str, Any] = None) -> dict:
        """
        Retrieve data for current observable
        """
        url = HttpUrl(f"{self.base_url}{endpoint}")
        response = self._request_data(
            type_request="GET", api_url=url, params=params or {}
        )
        return response.json()

    def post_data(self, endpoint: str, params: Dict[str, Any] = None) -> dict:
        """
        Send data for current observable
        """
        url = HttpUrl(f"{self.base_url}{endpoint}")
        response = self._request_data(
            type_request="POST", api_url=url, params=params or {}
        )
        return response.json()
