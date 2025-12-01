from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
    wait_fixed,
)

RETRYABLE_REQUEST_ERRORS = (
    requests.Timeout,
    requests.ConnectionError,
)


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.session = requests.Session()
        headers = {"x-api-key": self.config.api_key, "accept": "application/json"}
        # Add user_api_key if provided
        if self.config.user_api_key:
            headers["x-user-api-key"] = self.config.user_api_key
        if self.config.organization_code:
            headers["x-organization-code"] = self.config.organization_code

        self.session.headers.update(headers)

    @staticmethod
    def is_retryable_exception(exception):
        if isinstance(exception, requests.HTTPError):
            if exception.response.status_code in (429, 500, 502, 503, 504):
                return True

        if isinstance(exception, RETRYABLE_REQUEST_ERRORS):
            return True
        return False

    @retry(
        retry=retry_if_exception(is_retryable_exception),
        wait=wait_exponential_jitter(initial=10, max=60, jitter=1),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: response
        """
        try:
            response = self.session.get(api_url, params=params)
            response.raise_for_status()
            return response
        except requests.HTTPError as http_err:
            if http_err.response.status_code == 504:
                self.helper.connector_logger.warning(
                    "[API] Gateway Timeout, retrying...",
                    {"url": api_url, "params": params},
                )
                raise
            if http_err.response.status_code == 429:
                self.helper.connector_logger.warning(
                    "[API] Rate limited (429), retrying with backoff...",
                    {"url": api_url, "params": params},
                )
                raise
            else:
                try:
                    error_json = http_err.response.json()
                    error_msg = error_json.get("message", http_err.response.text)
                except Exception:
                    error_msg = http_err.response.text or str(http_err)

                self.helper.connector_logger.error(
                    "[API] HTTP error during fetch",
                    {
                        "url": api_url,
                        "status_code": http_err.response.status_code,
                        "error": error_msg,
                        "params": params,
                    },
                )
                raise
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Request error during fetch",
                {
                    "url": api_url,
                    "error": str(err),
                },
            )
            raise

    def _get_alerts(
        self, url: str, params: dict[str, Any], page: int, total_pages: int
    ) -> list:
        self.helper.connector_logger.info(
            "[DoppelConnector] Fetching page {}/{}".format(page, total_pages)
        )
        response = self._request_data(url, params={**params, "page": page})
        data = response.json()
        alerts = data.get("alerts", [])
        self.helper.connector_logger.info(
            "[DoppelConnector] Successfully fetched page {}/{} with {} alerts".format(
                page, total_pages, len(alerts)
            )
        )
        return alerts

    def get_alerts(
        self, last_activity_timestamp: str, page: int = 0, page_size: int = 100
    ) -> list:
        """
        Retrieve alerts from api
        """
        url = f"{self.config.api_base_url}{self.config.alerts_endpoint}"

        if last_activity_timestamp.endswith("+00:00"):
            last_activity_timestamp = last_activity_timestamp.replace("+00:00", "")

        # Dynamically set retry settings
        self._request_data.retry.wait = wait_fixed(self.config.retry_delay)
        self._request_data.retry.stop = stop_after_attempt(self.config.max_retries)

        params = {
            "last_activity_timestamp": last_activity_timestamp,
            "page": page,
            "page_size": page_size,
        }

        self.helper.connector_logger.info(
            "[DoppelConnector] Fetching first page of alerts",
            {"url": url, "params": params},
        )

        response = self._request_data(url, params=params)
        data = response.json()
        metadata = data.get("metadata", {})
        res = data.get("alerts", [])

        self.helper.connector_logger.info(
            "[DoppelConnector] Fetched first page of alerts",
            {"url": url, "params": params, "metadata": metadata},
        )
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(
                    self._get_alerts, url, params, page, metadata["total_pages"]
                )
                for page in range(1, metadata["total_pages"] + 1)
            ]
            for future in as_completed(futures):
                res.extend(future.result())
        return res
