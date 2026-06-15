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
        """Perform an HTTP request with retry/backoff on rate limiting and transient errors."""
        url = f"{self._base_url}{path}"
        for attempt in range(self.REQUEST_ATTEMPTS):
            try:
                response = self.session.request(
                    method, url, timeout=self.TIMEOUT, **kwargs
                )
                if response.status_code == 429 and attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                    continue
                response.raise_for_status()
                return response
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] Swimlane request failed",
                    {"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None
