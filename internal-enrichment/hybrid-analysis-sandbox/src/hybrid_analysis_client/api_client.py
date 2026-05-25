from typing import Literal

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter, Retry


class HybridAnalysisAPIError(Exception):
    """Custom exception for Hybrid Analysis API errors."""

    pass


class HybridAnalysisClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        token: str,
        environment_id: str = "110",
    ):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            token (str): The API token to authenticate the connector to the external API.
            environment_id (str): The environment ID for the Hybrid Analysis API.
        """
        self.helper = helper

        self.base_url = "https://hybrid-analysis.com/api/v2"
        self.environment_id = environment_id

        self.session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            allowed_methods=None,  # allow retry on any verb
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
            raise_on_status=True,
        )
        http_adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount(self.base_url, http_adapter)

        headers = {
            "api-key": token,
            "user-agent": "OpenCTI Hybrid Analysis Connector - Version 6.0.5",
            "accept": "application/json",
        }
        self.session.headers.update(headers)

    def _submit_request(
        self, method: Literal["GET", "POST"], endpoint: str, **kwargs
    ) -> requests.Response:
        """
        Internal method to handle API requests
        :param method: HTTP method to use for the request (e.g., "GET", "POST").
        :param endpoint: The API endpoint to send the request to (e.g., "/report/{report_id}/state").
        :param kwargs: Additional parameters to pass to the requests method (e.g., params, data, files).
        :return: Response in JSON format
        """
        try:
            url = self.base_url + endpoint
            response = self.session.request(method, url, **kwargs)

            self.helper.connector_logger.debug(
                "[API] HTTP Request to endpoint", {"method": method, "url": url}
            )

            response.raise_for_status()

            return response
        except requests.HTTPError as err:
            response_body = err.response.json()
            raise HybridAnalysisAPIError(
                f"API request error: {err.response.status_code} ({err.response.reason}) - {response_body.get('message')}"
            ) from err

    def get_report_state(self, report_id: str) -> dict:
        """
        Retrieve the analysis state for a given analysis ID.
        :param report_id: The ID of the analysis to retrieve the state for.
        :return: The analysis state if found, else None.
        """
        response = self._submit_request("GET", f"/report/{report_id}/state")
        return response.json()

    def get_report_summary(self, report_id: str):
        """
        Retrieve the analysis report for a given analysis ID.
        :param report_id: The ID of the analysis to retrieve the report for.
        :return: The analysis report if found, else None.
        """
        response = self._submit_request("GET", f"/report/{report_id}/summary")
        return response.json()

    def search_hash(self, hash_value: str) -> dict | None:
        """
        Search for a file hash in the Hybrid Analysis database.
        :param hash_value: The file hash to search for (MD5, SHA1, or SHA256).
        :return: The analysis results if found, else None.
        """
        params = {"hash": hash_value}

        try:
            response = self._submit_request("GET", "/search/hash", params=params)
            return response.json()
        except HybridAnalysisAPIError as err:
            if "Requested hash not found" in str(err):
                return None
            raise

    def submit_url(self, url: str) -> dict:
        """
        Submit a URL for analysis in the Hybrid Analysis sandbox.
        :param url: The URL to be analyzed.
        :return: The submission response from the API.
        """
        data = {
            "url": url,
            "environment_id": self.environment_id,
        }

        response = self._submit_request("POST", "/submit/url", data=data)
        return response.json()

    def submit_file(self, file_name: str, file_content: bytes) -> dict:
        """
        Submit a file for analysis in the Hybrid Analysis sandbox.
        :param file_name: The name of the file to be analyzed.
        :param file_content: The content of the file to be analyzed.
        :return: The submission response from the API.
        """
        files = {"file": (file_name, file_content)}
        data = {"environment_id": self.environment_id}

        response = self._submit_request("POST", "/submit/file", data=data, files=files)
        return response.json()
