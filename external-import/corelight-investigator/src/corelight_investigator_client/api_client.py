"""HTTP client for the Corelight Investigator Detections and Alerts API."""

from __future__ import annotations

import time
from typing import Optional

import requests
from pycti import OpenCTIConnectorHelper


class CorelightInvestigatorAPIError(Exception):
    """Custom exception for Corelight Investigator API errors."""


class CorelightInvestigatorClient:
    """Thin client around the Corelight Investigator Detections and Alerts API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 60

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_base_url: str,
        api_key: str,
        alerts_path: str = "/api/v1/alerts",
        max_alerts: int = 1000,
        ssl_verify: bool = True,
    ) -> None:
        """
        Initialize the Corelight Investigator client.

        :param helper: The OpenCTI connector helper (used for logging).
        :param api_base_url: The Investigator API base URL (region specific).
        :param api_key: The Investigator API key (Authorization bearer).
        :param alerts_path: The Detections and Alerts API endpoint path.
        :param max_alerts: Maximum number of alerts to request per run.
        :param ssl_verify: Whether to verify the TLS certificate.
        """
        self.helper = helper
        self._base_url = str(api_base_url).rstrip("/")
        self._alerts_path = "/" + alerts_path.lstrip("/")
        self._max_alerts = max_alerts

        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            }
        )

    def get_alerts(self, since: Optional[str] = None) -> list:
        """Fetch alerts/detections, optionally only those after ``since`` (ISO-8601)."""
        params: dict = {"limit": self._max_alerts}
        if since:
            params["start_time"] = since
        response = self._request("get", self._alerts_path, params=params)
        if response is None:
            return []
        try:
            return self._extract_alerts(response.json())
        except ValueError as err:
            raise CorelightInvestigatorAPIError(
                "Corelight Investigator returned a non-JSON response"
            ) from err

    @staticmethod
    def _extract_alerts(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("data", "alerts", "detections", "results", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    def _request(
        self, method: str, path: str, params: Optional[dict] = None
    ) -> Optional[requests.Response]:
        url = f"{self._base_url}{path}"
        for attempt in range(self.REQUEST_ATTEMPTS):
            try:
                response = self.session.request(
                    method, url, params=params, timeout=self.TIMEOUT
                )
                if response.status_code == 429 and attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                    continue
                response.raise_for_status()
                return response
            except requests.HTTPError as err:
                status = err.response.status_code if err.response is not None else 0
                if status >= 500 and attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                    continue
                raise CorelightInvestigatorAPIError(
                    f"Corelight Investigator API error: {status} ({err})"
                ) from err
            except requests.RequestException as err:
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                    continue
                raise CorelightInvestigatorAPIError(
                    f"Corelight Investigator request failed: {err}"
                ) from err
        return None
