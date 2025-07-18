import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .endpoints import BASE_URL


class CVEClient:
    """
    Working with CVE API
    """

    def __init__(self, api_key, helper, header):
        """
        Initialize CVE API with necessary configurations
        :param api_key: API key in string
        :param helper: OCTI helper
        :param header:
        """
        headers = {"apiKey": api_key, "User-Agent": header}
        self.token = api_key
        self.helper = helper
        self.session = requests.Session()
        self.session.headers.update(headers)

    @staticmethod
    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.request(api_url, params)

            info_msg = f"[API] HTTP Get Request to endpoint for path ({api_url})"
            self.helper.connector_logger.info(info_msg)

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = f"[API] Error while fetching data from {api_url}: {str(err)}"
            self.helper.connector_logger.error(error_msg, meta={"error": str(err)})
            return None

    def request(self, api_url, params):
        # Define the retry strategy
        retry_strategy = Retry(
            total=4,  # Maximum number of retries
            backoff_factor=6,  # Exponential backoff factor (e.g., 2 means 1, 2, 4, 8 seconds, ...)
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        )
        # Create an HTTP adapter with the retry strategy and mount it to session
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        response = self.session.get(api_url, params=params)

        if response.status_code == 200:
            # It is recommended that users "sleep" their scripts for six seconds between requests (NIST)
            time.sleep(6)
            return response
        elif response.status_code == 404:
            error_data = response.headers
            if error_data.get("message") == "Invalid apiKey.":
                raise Exception(
                    "[API] Invalid API Key provided. Please check your configuration."
                )
            else:
                raise Exception(f"[API] Error: {error_data.get('message')}")
        raise Exception(
            "[API] Attempting to retrieve data failed. Wait for connector to re-run..."
        )

    def get_complete_collection(self, cve_params=None):
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param cve_params: Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            response = self._request_data(self, BASE_URL, params=cve_params)

            cve_collection = response.json()
            return cve_collection

        except Exception as err:
            self.helper.connector_logger.error(err, meta={"error": str(err)})
