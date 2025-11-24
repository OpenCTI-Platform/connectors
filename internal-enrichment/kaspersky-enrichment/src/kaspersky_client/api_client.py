import requests
from pycti import OpenCTIConnectorHelper


class KasperskyClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str | object,
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

    def get_file_info(self, obs_hash) -> dict:
        """
        Retrieve file information
        """
        try:
            file_url = f"{self.base_url}api/hash/{obs_hash}"
            response = self._request_data(file_url, params=self.params)
            return response.json()
        except Exception as err:
            self.helper.connector_logger.error(err)
