"""HTTP client for the FortiEDR Central Manager REST API (IP Sets)."""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

# FortiEDR IP Sets only handle IP addresses. Other observable types (file hashes,
# domains, URLs) are best ingested through FortiEDR's native STIX/TAXII Threat
# Intelligence Feed pointed at OpenCTI's TAXII server (see README).
# The value may be single- or double-quoted: STIX 2.1 string literals use single
# quotes, but double quotes are accepted defensively so valid IP indicators are
# not silently skipped.
SUPPORTED_STIX_PATTERNS = {
    "ipv4-addr": re.compile(
        r"""^\s*\[ipv4-addr:value\s*=\s*(['"])(?P<value>[^'"]+)\1\s*\]\s*$"""
    ),
    "ipv6-addr": re.compile(
        r"""^\s*\[ipv6-addr:value\s*=\s*(['"])(?P<value>[^'"]+)\1\s*\]\s*$"""
    ),
}

IP_SETS_PATH = "/management-rest/ip-sets"


def extract_ip(pattern: str) -> Optional[str]:
    """Return the IP value of a supported single-observable STIX pattern, or None."""
    if not pattern:
        return None
    for regex in SUPPORTED_STIX_PATTERNS.values():
        match = regex.match(pattern)
        if match:
            return match.group("value")
    return None


class FortiEDRClient:
    """Thin client around the FortiEDR Central Manager IP Sets API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the FortiEDR client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.fortiedr

        self._base_url = str(self.config.api_base_url).rstrip("/")

        user = self.config.username
        if self.config.organization:
            user = f"{self.config.organization}\\{self.config.username}"

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.auth = (user, self.config.password.get_secret_value())
        self.session.headers.update({"Content-Type": "application/json"})

    def add_indicator(self, indicator: dict) -> bool:
        """
        Add an IP indicator to the managed FortiEDR IP Set.

        :param indicator: The STIX indicator object received from the live stream.
        :return: True if the IP was added (or already present), False if skipped/failed.
        """
        ip = extract_ip(indicator.get("pattern", ""))
        if ip is None:
            return False
        return self._update_membership(ip, add=True)

    def remove_indicator(self, indicator: dict) -> bool:
        """
        Remove an IP indicator from the managed FortiEDR IP Set.

        :param indicator: The STIX indicator object received from the live stream.
        :return: True if the IP was removed (or absent), False if skipped/failed.
        """
        ip = extract_ip(indicator.get("pattern", ""))
        if ip is None:
            return False
        return self._update_membership(ip, add=False)

    def _update_membership(self, ip: str, add: bool) -> bool:
        ip_sets = self._list_ip_sets()
        if ip_sets is None:
            # The list request failed: do not guess membership. Creating or
            # rewriting the set blindly could clobber it, and reporting
            # success for a removal would be wrong.
            return False

        ip_set = self._find_ip_set(ip_sets)
        ips = list(ip_set["ips"]) if ip_set else []

        if add:
            if ip in ips:
                return True
            ips.append(ip)
        else:
            if ip not in ips:
                return True
            ips.remove(ip)

        return self._save_ip_set(ips, exists=ip_set is not None)

    @staticmethod
    def _extract_sets(payload) -> list:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("ipSets", "ip_sets", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    @staticmethod
    def _extract_ips(ip_set: dict) -> list:
        for key in ("include", "ips", "ipList", "addresses"):
            value = ip_set.get(key)
            if isinstance(value, list):
                return value
        return []

    def _list_ip_sets(self) -> Optional[list]:
        """Return the raw list of IP Sets, or None if the request failed."""
        response = self._request("get", f"{IP_SETS_PATH}/list-ip-sets")
        if response is None:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        return self._extract_sets(payload)

    def _find_ip_set(self, ip_sets: list) -> Optional[dict]:
        for ip_set in ip_sets:
            if (
                isinstance(ip_set, dict)
                and ip_set.get("name") == self.config.ip_set_name
            ):
                return {"name": ip_set.get("name"), "ips": self._extract_ips(ip_set)}
        return None

    def _save_ip_set(self, ips: list, exists: bool) -> bool:
        payload = {"name": self.config.ip_set_name, "include": ips}
        if exists:
            response = self._request(
                "put", f"{IP_SETS_PATH}/update-ip-set", json=payload
            )
        else:
            response = self._request(
                "post", f"{IP_SETS_PATH}/create-ip-set", json=payload
            )
        return response is not None

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
                    "[API] FortiEDR request failed",
                    meta={"url": url, "error": str(err)},
                )
                if last_attempt:
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            if response.status_code == 429 or response.status_code >= 500:
                if last_attempt:
                    self.helper.connector_logger.warning(
                        "[API] FortiEDR request failed",
                        meta={"url": url, "status_code": response.status_code},
                    )
                    return None
                time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as err:
                self.helper.connector_logger.warning(
                    "[API] FortiEDR request failed",
                    meta={"url": url, "error": str(err)},
                )
                return None
            return response
        return None
