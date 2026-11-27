import time

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class SilentpushClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
        verify: bool,
    ):
        """Initialize the Silent Push API client.

        :param helper: Connector helper, used for logging.
        :param base_url: Silent Push API base URL.
        :param api_key: API key for authentication.
        :param verify: Whether to verify SSL certificates.
        """
        self.helper = helper

        self.base_url = base_url
        self.verify = verify
        # Define headers in session and update when needed
        headers = {"User-Agent": "OpenCTI", "x-api-key": api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def ping(self):
        try:
            response = self.session.get(f"{self.base_url}me/", verify=self.verify, timeout=(10, 30))
            response.raise_for_status()
            self.helper.connector_logger.debug(
                f"[API] HTTP GET request /me \n{response.json()}"
            )
            if response.status_code != 200:
                return False
            return True
        except Exception as e:
            self.helper.connector_logger.debug(f"ping error: {e}")
            return False

    def _request_data(self, api_url: str, payload=None) -> dict | None:
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            method = "POST" if payload else "GET"
            response = self.session.request(
                method, api_url, json=payload, verify=self.verify
            )
            self.helper.connector_logger.info(
                f"[API] HTTP {method} request",
                {"url": api_url},
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_enrichment_data(self, api_type: str, value: str) -> dict | None:
        """Fetch enrichment data from Silent Push API.

        :param api_type: API type (e.g. ipv4, domain).
        :param value: Observable value.
        :return: Parsed JSON response or None on error.
        """
        enrichment_url = f"{self.base_url}enrich/{api_type}/{value}/"

        return self._request_data(enrichment_url)

    def get_diversity_data(self, value: str) -> dict | None:
        """Fetch PADNS diversity data from Silent Push API.

        :param value: Domain name.
        :return: Parsed JSON response or None on error.
        """
        diversity_url = f"{self.base_url}enrich/domain/{value}/ip-diversity/"

        return self._request_data(diversity_url)

    def is_job_response(self, data) -> bool:
        """
        job response format is always `{"job_id":"abcde123-12ab-34cd-56ef-123456abcdef"}`
        """
        return (
            isinstance(data, dict)
            and data.keys() == {"job_id"}
            and isinstance(data["job_id"], str)
            and data["job_id"] != ""
        )

    def retry_job(self, job_id: str) -> list:
        """
        retry 10x to get a job response
        """
        records = []
        for attempt in range(1, 11):
            self.helper.connector_logger.debug(f"attempt {attempt} job '{job_id}'")
            response = self._request_data(
                f"{self.base_url}job/{job_id}?max_wait={attempt * 3}"
            )
            records = (response or {}).get("records", []) or []
            if records:
                self.helper.connector_logger.debug("successfully got results for job")
                break
            if attempt < 10:
                time.sleep(attempt * 3)
        return records

    def get_webscan(self, value: str, _type: str = "domain") -> list:
        """
        Fetch webscan data for Domain or IP from Silent Push API.
        """
        webscan_url = f"{self.base_url}spql-search/?max_wait=30"
        payload = {
            "query": f'{_type}="{value}" AND datasource=["webscan"]',
            "sort": ["scan_date/desc"],
        }
        webscan_data = self._request_data(webscan_url, payload=payload)
        self.helper.connector_logger.debug(f"webscan_data '{webscan_data}'")
        if webscan_data is None:
            self.helper.connector_logger.warning(
                f"webscan request failed for '{value}'"
            )
            return []
        records = []
        if self.is_job_response(webscan_data):
            records = self.retry_job(webscan_data["job_id"])
        return (webscan_data.get("data", []) or records)[:7]
