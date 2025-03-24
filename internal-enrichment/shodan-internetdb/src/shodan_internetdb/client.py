import requests
from pydantic.v1 import BaseModel, parse_raw_as

__all__ = [
    "ShodanInternetDbClient",
    "ShodanResult",
]


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

    def query(self, ip: str) -> ShodanResult | None:
        """Process the IP and return the result
        :return: Query result
        """
        resp = self._session.get(
            f"{self._base_url}{ip}",
            headers=self._headers,
            verify=self._verify,
        )

        # {'detail': 'No information available'}
        if resp.status_code == 404:
            return None

        resp.raise_for_status()

        return parse_raw_as(ShodanResult, resp.text)
