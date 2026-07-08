"""HTTP client for the FortiSIEM REST API (incidents)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

INCIDENTS_PATH = "/phoenix/rest/pub/incident"


class FortiSIEMClientError(Exception):
    """Raised when FortiSIEM cannot be reached or returns an invalid response."""


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
        :return: A list of incident dictionaries (possibly empty when there are
            genuinely no new incidents).
        :raises FortiSIEMClientError: when the request fails (a network error
            after retries, or a non-retriable HTTP error) or returns a non-JSON
            body. This is distinct from "no new incidents" so the caller does not
            advance its state past a window it never actually fetched (which would
            silently skip incidents).
        """
        response = self._request("get", INCIDENTS_PATH, params={"update_from": since})
        if response is None:
            # _request returns None both for network errors after retries and for
            # a non-retriable 4xx (where a response did exist), so keep the message
            # generic; the specifics (url, status_code, error) are logged there.
            raise FortiSIEMClientError("Failed to fetch FortiSIEM incidents")
        try:
            return self._extract_incidents(response.json())
        except ValueError as err:
            raise FortiSIEMClientError(
                "FortiSIEM returned a non-JSON incidents response"
            ) from err

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
        """
        Perform an HTTP request with retry/backoff.

        Connection/timeout errors, rate limiting (429) and server-side errors
        (5xx) are retried; other 4xx responses (e.g. 401/403/404) fail fast
        without retrying, since retrying them only adds delay and log noise.
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
                    "[API] FortiSIEM request failed",
                    meta={"url": url, "error": str(err)},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] FortiSIEM request failed",
                        meta={"url": url, "status_code": response.status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] FortiSIEM request failed",
                    meta={"url": url, "error": str(err)},
                )
                return None
            return response
        return None
