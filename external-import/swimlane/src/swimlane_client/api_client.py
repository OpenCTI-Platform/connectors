"""HTTP client for the Swimlane REST API (records)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class SwimlaneClient:
    """Thin client around the Swimlane record search API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 60

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the Swimlane client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.swimlane

        self._base_url = str(self.config.api_base_url).rstrip("/")

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update(
            {
                "Private-Token": self.config.api_token.get_secret_value(),
                "Content-Type": "application/json",
            }
        )

    def get_records(self) -> list:
        """Fetch records from the configured Swimlane application."""
        path = f"/api/app/{self.config.application_id}/record/search"
        body = {
            "filters": [],
            "pageSize": self.config.max_records,
            "pageNumber": 0,
        }
        response = self._request("post", path, json=body)
        if response is None:
            return []
        try:
            return self._extract_records(response.json())
        except ValueError:
            self.helper.connector_logger.error(
                "[API] Unexpected Swimlane records response"
            )
            return []

    @staticmethod
    def _extract_records(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("results", "docs", "records", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform an HTTP request with retry/backoff.

        Connection/timeout errors, rate limiting (429) and server-side errors
        (5xx) are retried; other 4xx responses (e.g. 401/403/404) fail fast
        without retrying, since retrying them only adds delay and log noise.
        Structured context is passed via ``meta={...}``.
        """
        url = f"{self._base_url}{path}"
        for attempt in range(self.REQUEST_ATTEMPTS):
            last_attempt = attempt == self.REQUEST_ATTEMPTS - 1
            try:
                response = self.session.request(
                    method, url, timeout=self.TIMEOUT, **kwargs
                )
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] Swimlane request failed",
                    meta={"url": url, "error_type": type(err).__name__},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] Swimlane request failed",
                        meta={"url": url, "status_code": response.status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] Swimlane request failed",
                    meta={
                        "url": url,
                        "status_code": response.status_code,
                        "error_type": type(err).__name__,
                    },
                )
                return None
            return response
        return None
