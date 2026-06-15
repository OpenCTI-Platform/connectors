"""HTTP client for the LogRhythm Case API."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

CASES_PATH = "/lr-case-api/cases"


class LogRhythmClient:
    """Thin client around the LogRhythm Case API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 60

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the LogRhythm client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.logrhythm_incidents

        self._base_url = str(self.config.api_base_url).rstrip("/")

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.config.api_token.get_secret_value()}",
                "Accept": "application/json",
            }
        )

    def get_cases(self) -> list:
        """Fetch LogRhythm cases, capped at the configured maximum."""
        response = self._request(
            "get", CASES_PATH, params={"count": self.config.max_cases}
        )
        if response is None:
            return []
        try:
            return self._extract_cases(response.json())
        except ValueError:
            self.helper.connector_logger.error(
                "[API] Unexpected LogRhythm cases response"
            )
            return []

    @staticmethod
    def _extract_cases(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("cases", "items", "data", "results"):
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
                    "[API] LogRhythm request failed",
                    {"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None
