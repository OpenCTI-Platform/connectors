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
                # The entry-management response body is not used; release the
                # connection back to the Session pool instead of leaving it
                # checked out until garbage collection.
                response.close()
                return True
            # token may have expired, force a re-login on the next attempt
            self._token = None
        return False

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform an HTTP request with retry/backoff.

        Connection/timeout errors, rate limiting (429) and server-side errors
        (5xx) are retried; other 4xx responses (e.g. 401/403/404) fail fast
        without retrying. Failing fast on 401 also lets `_post_entries` trigger a
        token re-issue immediately instead of after three backoff sleeps.

        Errors are logged with the exception type and status code only - never
        ``str(err)`` - because the login request carries the ArcSight password as
        a query parameter and a ``requests`` exception string usually embeds the
        full request URL, which would leak the credentials into the logs.
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
                    "[API] ArcSight request failed",
                    meta={"path": path, "error_type": type(err).__name__},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                status_code = response.status_code
                # Release the connection back to the Session pool before
                # sleeping/returning: the body is never consumed on this path.
                response.close()
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] ArcSight request failed",
                        meta={"path": path, "status_code": status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] ArcSight request failed",
                    meta={
                        "path": path,
                        "status_code": response.status_code,
                        "error_type": type(err).__name__,
                    },
                )
                response.close()
                return None
            return response
        return None
