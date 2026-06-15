"""HTTP client for the ArcSight ESM Service Layer REST API (Active Lists)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from arcsight_client.stix_patterns import extract_value
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

LOGIN_PATH = "/www/core-service/rest/LoginService/login"
ADD_ENTRIES_PATH = "/www/manager-service/rest/ActiveListService/addEntries"
DELETE_ENTRIES_PATH = "/www/manager-service/rest/ActiveListService/deleteEntries"


class ArcSightClient:
    """Thin client around the ArcSight ESM Active List API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the ArcSight client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.arcsight

        self._base_url = str(self.config.api_base_url).rstrip("/")
        self._token: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

    def add_indicator(self, indicator: dict) -> bool:
        """Add an indicator value to the configured ArcSight Active List."""
        value = extract_value(indicator.get("pattern", ""))
        if value is None:
            return False
        return self._post_entries(ADD_ENTRIES_PATH, "act.addEntries", value)

    def remove_indicator(self, indicator: dict) -> bool:
        """Remove an indicator value from the configured ArcSight Active List."""
        value = extract_value(indicator.get("pattern", ""))
        if value is None:
            return False
        return self._post_entries(DELETE_ENTRIES_PATH, "act.deleteEntries", value)

    def _get_token(self, force: bool = False) -> Optional[str]:
        if self._token is not None and not force:
            return self._token
        params = {
            "login": self.config.username,
            "password": self.config.password.get_secret_value(),
            "alt": "json",
        }
        response = self._request("get", LOGIN_PATH, params=params)
        if response is None:
            return None
        try:
            self._token = response.json()["log.loginResponse"]["log.return"]
        except (ValueError, KeyError):
            self.helper.connector_logger.error(
                "[API] Unexpected ArcSight login response"
            )
            return None
        return self._token

    def _build_body(self, operation: str, token: str, value: str) -> dict:
        return {
            operation: {
                "act.authToken": token,
                "act.resourceId": self.config.active_list_id,
                "act.entryList": {
                    "columns": [self.config.value_column],
                    "entryList": [{"entry": [value]}],
                },
            }
        }

    def _post_entries(self, path: str, operation: str, value: str) -> bool:
        for attempt in range(2):  # allow one re-authentication
            token = self._get_token(force=attempt > 0)
            if token is None:
                return False
            response = self._request(
                "post", path, json=self._build_body(operation, token, value)
            )
            if response is not None:
                return True
            # token may have expired, force a re-login on the next attempt
            self._token = None
        return False

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
                    "[API] ArcSight request failed",
                    {"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None
