import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class KasperskyClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str | HttpUrl,
        api_key: str,
        params: dict,
    ):
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
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.params = params

    def _request_data(self, api_url: str, params: dict) -> requests.Response:
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

        except requests.exceptions.HTTPError as errh:
            if response.status_code == 401:
                msg = "Permissions Error, Kaspersky returned a 401, please check your API key"
            elif response.status_code == 404:
                msg = "File not found on Kaspersky, no enrichment possible"
            else:
                msg = "Http error"
            self.helper.connector_logger.error(msg, {"error": errh})
            raise
        except requests.exceptions.ConnectionError as errc:
            self.helper.connector_logger.error("Error connecting", {"error": errc})
            raise
        except requests.exceptions.Timeout as errt:
            self.helper.connector_logger.error("Timeout error", {"error": errt})
            raise
        except requests.exceptions.RequestException as err:
            self.helper.connector_logger.error(
                "Something else happened", {"error": err}
            )
            raise
        except Exception as err:
            self.helper.connector_logger.error("Unknown error", {"error": err})
            raise

    def get_file_info(self, obs_hash: str) -> dict:
        """
        Retrieve file information
        """
        file_url = f"{self.base_url}api/hash/{obs_hash}"
        response = self._request_data(file_url, params=self.params)
        return response.json()
