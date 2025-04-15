import requests
from pydantic.v1 import BaseModel, parse_raw_as

__all__ = [
    "ShodanInternetDbClient",
    "ShodanResult",
]

from shodan_internetdb.exceptions import (
    ShodanInternetDbApiError,
    ShodanInternetDbNotFoundError,
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

    def __init__(self, verify: bool = True):
        """
        Constructor
        :param verify: Verify SSL connections
        """
        self._base_url = "https://internetdb.shodan.io/"
        self._headers = {"Accept": "application/json"}
        self._session = requests.Session()
        self._verify = verify

    def query(self, ip: str) -> ShodanResult:
        """Process the IP and return the result
        :return: Query result
        """
        try:
            resp = self._session.get(
                f"{self._base_url}{ip}",
                headers=self._headers,
                verify=self._verify,
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

        resp.raise_for_status()

        return parse_raw_as(ShodanResult, resp.text)
