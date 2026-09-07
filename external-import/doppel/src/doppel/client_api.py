from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

import requests
from doppel.constants import DOPPEL_ATTRIBUTION_HEADERS, RETRYABLE_REQUEST_ERRORS
from doppel.oauth import OAuthTokenProvider
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
    wait_fixed,
)

if TYPE_CHECKING:
    from doppel import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class ConnectorClient:
    def __init__(self, helper: "OpenCTIConnectorHelper", config: "ConnectorSettings"):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        configured_base_url = str(self.config.doppel.api_base_url).rstrip("/")
        api_root = self._strip_api_version(configured_base_url)
        self.api_base_url = f"{api_root}/{self.config.doppel.api_version}"

        self.session = requests.Session()
        headers = {
            **DOPPEL_ATTRIBUTION_HEADERS,
            "accept": "application/json",
        }
        self.oauth_token_provider: OAuthTokenProvider | None = None

        if self.config.doppel.api_version == "v1":
            api_key = self.config.doppel.api_key
            if api_key is None:
                raise ValueError("Doppel V1 api_key is required")
            headers["x-api-key"] = api_key.get_secret_value()
            if self.config.doppel.user_api_key:
                headers["x-user-api-key"] = (
                    self.config.doppel.user_api_key.get_secret_value()
                )
            if self.config.doppel.organization_code:
                headers["x-organization-code"] = self.config.doppel.organization_code
        else:
            client_id = self.config.doppel.client_id
            client_secret = self.config.doppel.client_secret
            if client_id is None or client_secret is None:
                raise ValueError("Doppel V2 client credentials are required")
            token_url = (
                str(self.config.doppel.token_url).rstrip("/")
                if self.config.doppel.token_url
                else f"{api_root}/oauth/token"
            )
            self.oauth_token_provider = OAuthTokenProvider(
                token_url=token_url,
                client_id=client_id,
                client_secret=client_secret.get_secret_value(),
                audience=self.config.doppel.token_audience,
            )

        self.session.headers.update(headers)

    @staticmethod
    def _strip_api_version(base_url: str) -> str:
        """Remove a configured API version so the selected version is authoritative."""
        for suffix in ("/v1", "/v2"):
            if base_url.endswith(suffix):
                return base_url[: -len(suffix)]
        return base_url

    def _authenticated_get(self, api_url: str, params=None):
        """Issue a GET and refresh a rejected V2 token once."""
        if self.oauth_token_provider is None:
            return self.session.get(api_url, params=params)

        access_token = self.oauth_token_provider.get_token()
        response = self.session.get(
            api_url,
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 401:
            return response

        response.close()
        access_token = self.oauth_token_provider.refresh_after_unauthorized(
            access_token
        )
        return self.session.get(
            api_url,
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )

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
            response = self._authenticated_get(api_url, params=params)
            response.raise_for_status()
            return response
        except requests.HTTPError as http_err:
            if http_err.response.status_code == 504:
                self.helper.connector_logger.warning(
                    "[API] Gateway Timeout, retrying...",
                    {"url": api_url, "params": params},
                )
                raise
            elif http_err.response.status_code == 429:
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
        alerts_endpoint = self.config.doppel.alerts_endpoint.lstrip("/")
        for prefix in ("v1/", "v2/"):
            if alerts_endpoint.startswith(prefix):
                alerts_endpoint = alerts_endpoint[len(prefix) :]
                break
        url = f"{self.api_base_url}/{alerts_endpoint}"

        # Dynamically set retry settings
        self._request_data.retry.wait = wait_fixed(self.config.doppel.retry_delay)
        self._request_data.retry.stop = stop_after_attempt(
            self.config.doppel.max_retries
        )

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
