"""HTTP client for the FortiSIEM REST API (Watch Lists)."""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

ADD_TO_PATH = "/phoenix/rest/watchlist/addTo"

# Single-observable STIX 2.1 patterns whose value can be pushed as a Watch List
# entry. Watch List entries are generic values, so IPs, domains, URLs and file
# hashes are all supported.
SUPPORTED_STIX_PATTERNS = [
    re.compile(r"^\s*\[ipv4-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[ipv6-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[domain-name:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[url:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(
        r"^\s*\[file:hashes\.(?i:'?(?:MD5|SHA-?1|SHA-?256)'?)\s*=\s*'([^']+)'\s*\]\s*$"
    ),
]


def extract_value(pattern: str) -> Optional[str]:
    """Return the observable value of a supported single-observable STIX pattern, or None."""
    if not pattern:
        return None
    for regex in SUPPORTED_STIX_PATTERNS:
        match = regex.match(pattern)
        if match:
            return match.group(1)
    return None


class FortiSIEMClient:
    """Thin client around the FortiSIEM Watch List API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the FortiSIEM client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.fortisiem

        self._base_url = str(self.config.api_base_url).rstrip("/")

        user = self.config.username
        if self.config.organization:
            user = f"{self.config.organization}/{self.config.username}"

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.auth = (user, self.config.password.get_secret_value())
        self.session.headers.update({"Content-Type": "application/json"})

    def add_indicator(self, indicator: dict) -> bool:
        """
        Add an indicator value to the configured FortiSIEM Watch List.

        :param indicator: The STIX indicator object received from the live stream.
        :return: True if the entry was sent, False if it was skipped/failed.
        """
        value = extract_value(indicator.get("pattern", ""))
        if value is None:
            return False

        body = {
            "parameters": {"watchlistId": self.config.watchlist_id},
            "json_body": [
                {
                    "entryValue": value,
                    "state": "Enabled",
                    "description": "OpenCTI indicator",
                    "ageOut": self.config.entry_age_out,
                }
            ],
        }
        response = self._request("post", ADD_TO_PATH, json=body)
        if response is None:
            return False
        # The response body is not used: release the connection back to the
        # session pool, consistent with the retry/error paths in _request.
        response.close()
        return True

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform an HTTP request with retry/backoff.

        Connection and timeout errors, rate limiting (429) and server-side errors
        (5xx) are retried. Other request failures (e.g. invalid URL/schema) and 4xx
        responses (e.g. 401/403/404) fail fast without retrying, since retrying them
        only adds delay and log noise.
        """
        url = f"{self._base_url}{path}"
        for attempt in range(self.REQUEST_ATTEMPTS):
            last_attempt = attempt == self.REQUEST_ATTEMPTS - 1
            try:
                response = self.session.request(
                    method, url, timeout=self.TIMEOUT, **kwargs
                )
            except (requests.ConnectionError, requests.Timeout) as err:
                # Transient connection/timeout error: retry with backoff.
                self.helper.connector_logger.warning(
                    "[API] FortiSIEM request failed",
                    meta={"url": url, "error": str(err)},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue
            except requests.RequestException as err:
                # Non-transient request error (e.g. invalid URL/schema): fail fast.
                self.helper.connector_logger.warning(
                    "[API] FortiSIEM request failed",
                    meta={"url": url, "error": str(err)},
                )
                return None

            if response.status_code == 429 or response.status_code >= 500:
                status_code = response.status_code
                # Release the connection back to the pool before sleeping/retrying
                # or returning, since the response body is not consumed here.
                response.close()
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] FortiSIEM request failed",
                        meta={"url": url, "status_code": status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                # Release the connection back to the pool on a non-retriable 4xx.
                response.close()
                self.helper.connector_logger.warning(
                    "[API] FortiSIEM request failed",
                    meta={"url": url, "error": str(err)},
                )
                return None
            return response
        return None
