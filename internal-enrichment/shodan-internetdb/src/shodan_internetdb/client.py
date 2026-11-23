import requests
from pydantic.v1 import BaseModel, parse_raw_as

__all__ = [
    "ShodanInternetDbClient",
    "ShodanResult",
]

from shodan_internetdb.exceptions import (
    ShodanInternetDbApiError,
    ShodanInternetDbNotFoundError,
    ShodanInternetDbRateLimitError,
)


class ShodanResult(BaseModel):
    """Shodan InternetDB response"""

    cpes: list[str]  # Common Platform Enumeration (CPE)
    hostnames: list[str]
    ip: str
    ports: list[int]
    tags: list[str]
    vulns: list[str]


class ShodanInternetDbClient:
    """Shodan InternetDB client"""

    def __init__(self, verify: bool = True, timeout: int = 30):
        """
        Constructor
        :param verify: Verify SSL connections
        :param timeout: Request timeout in seconds
        """
        self._base_url = "https://internetdb.shodan.io/"
        self._headers = {"Accept": "application/json"}
        self._session = requests.Session()
        self._verify = verify
        self._timeout = timeout

    def query(self, ip: str) -> ShodanResult:
        """Process the IP and return the result
        :return: Query result
        """
        try:
            resp = self._session.get(
                f"{self._base_url}{ip}",
                headers=self._headers,
                verify=self._verify,
                timeout=self._timeout,
            )
        except Exception as e:
            raise ShodanInternetDbApiError(
                "[CONNECTOR] Skipping observable (Shodan API error)"
            ) from e

        # {'detail': 'No information available'}
        if resp.status_code == 404:
            raise ShodanInternetDbNotFoundError(
                "[CONNECTOR] No information available, skipping observable (Shodan 404)"
            )

        # Rate limited: fail the work with a clear message (Retry-After can be an hour or more)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "unknown")
            raise ShodanInternetDbRateLimitError(
                "[CONNECTOR] Shodan InternetDB rate limit reached (HTTP 429), "
                f"Retry-After: {retry_after}s; observable not enriched"
            )

        resp.raise_for_status()

        return parse_raw_as(ShodanResult, resp.text)
