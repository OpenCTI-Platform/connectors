import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.base_url = base_url

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: HttpUrl, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(str(api_url), params=params)

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

    def get_entity(self, params=None) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """

        try:
            response = self._request_data(self.base_url, params=params)

            return response.json()

        except Exception as err:
            error_msg = "[API] Error while parsing data: "
            self.helper.connector_logger.error(error_msg, {"error": {str(err)}})
