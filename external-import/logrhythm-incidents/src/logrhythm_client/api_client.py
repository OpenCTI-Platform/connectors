"""HTTP client for the LogRhythm Case API."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

CASES_PATH = "/lr-case-api/cases"
CASE_ALARMS_PATH = "/lr-case-api/cases/{case_id}/evidence/alarms"


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
            return self._extract_list(
                response.json(), ("cases", "items", "data", "results")
            )
        except ValueError:
            self.helper.connector_logger.error(
                "[API] Unexpected LogRhythm cases response"
            )
            return []

    def get_case_alarms(self, case_id) -> list:
        """Fetch the alarm evidence attached to a LogRhythm case."""
        path = CASE_ALARMS_PATH.format(case_id=case_id)
        response = self._request("get", path)
        if response is None:
            return []
        try:
            return self._extract_list(
                response.json(), ("alarms", "items", "data", "results")
            )
        except ValueError:
            return []

    @staticmethod
    def _extract_list(payload, keys) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in keys:
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
                    "[API] LogRhythm request failed",
                    meta={"url": url, "error_type": type(err).__name__},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] LogRhythm request failed",
                        meta={"url": url, "status_code": response.status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] LogRhythm request failed",
                    meta={
                        "url": url,
                        "status_code": response.status_code,
                        "error_type": type(err).__name__,
                    },
                )
                return None
            return response
        return None
