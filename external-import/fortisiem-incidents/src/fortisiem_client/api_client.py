"""HTTP client for the FortiSIEM REST API (incidents)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

INCIDENTS_PATH = "/phoenix/rest/pub/incident"


class FortiSIEMClient:
    """Thin client around the FortiSIEM incidents REST API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 60

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the FortiSIEM client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.fortisiem_incidents

        self._base_url = str(self.config.api_base_url).rstrip("/")

        user = self.config.username
        if self.config.organization:
            user = f"{self.config.organization}/{self.config.username}"

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.auth = (user, self.config.password.get_secret_value())
        self.session.headers.update({"Accept": "application/json"})

    def get_incidents(self, since: str) -> list:
        """
        Fetch FortiSIEM incidents updated since the given timestamp.

        :param since: ISO-8601 timestamp used as the lower bound.
        :return: A list of incident dictionaries (empty on failure).
        """
        response = self._request("get", INCIDENTS_PATH, params={"update_from": since})
        if response is None:
            return []
        try:
            return self._extract_incidents(response.json())
        except ValueError:
            self.helper.connector_logger.error(
                "[API] Unexpected FortiSIEM incidents response"
            )
            return []

    @staticmethod
    def _extract_incidents(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("incidents", "data", "result", "results"):
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
                    "[API] FortiSIEM request failed",
                    {"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None
