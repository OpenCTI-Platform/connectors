"""HTTP client for the Swimlane REST API (records)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class SwimlaneClientError(Exception):
    """Raised when Swimlane cannot be reached or returns an invalid response."""


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
        """
        Fetch records from the configured Swimlane application.

        :return: A list of record dictionaries (possibly empty when there are
            genuinely no records).
        :raises SwimlaneClientError: when the request fails (no response after
            retries, or a non-retriable HTTP error) or returns a non-JSON /
            unexpected body. This is kept distinct from "no records" so a transient
            Swimlane failure surfaces as a run error (work marked ``in_error``)
            instead of being silently reported as a successful empty run.
        """
        path = f"/api/app/{self.config.application_id}/record/search"
        body = {
            "filters": [],
            "pageSize": self.config.max_records,
            "pageNumber": 0,
        }
        response = self._request("post", path, json=body)
        if response is None:
            raise SwimlaneClientError("Failed to fetch Swimlane records")
        try:
            payload = response.json()
        except ValueError as err:
            raise SwimlaneClientError(
                "Swimlane returned a non-JSON records response"
            ) from err
        return self._extract_records(payload)

    @staticmethod
    def _extract_records(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("results", "docs", "records", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        raise SwimlaneClientError(
            "Swimlane returned an unexpected records payload shape"
        )

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
                status_code = response.status_code
                # Release the connection back to the Session pool: the body is
                # never consumed on this retry/error path.
                response.close()
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] Swimlane request failed",
                        meta={"url": url, "status_code": status_code},
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
                response.close()
                return None
            return response
        return None
