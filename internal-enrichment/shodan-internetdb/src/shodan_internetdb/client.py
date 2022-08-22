"""Shodan InternetDB client"""

from __future__ import annotations

from typing import List, Optional

import pydantic
import requests
from pydantic import BaseModel

__all__ = [
    "ShodanInternetDbClient",
    "ShodanResult",
]


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

    def query(self, ip: str) -> Optional[ShodanResult]:
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

        return pydantic.parse_raw_as(ShodanResult, resp.text)


class ShodanResult(BaseModel):
    """Shodan InternetDB response"""

    cpes: List[str]  # Common Platform Enumeration (CPE)
    hostnames: List[str]
    ip: str
    ports: List[int]
    tags: List[str]
    vulns: List[str]
