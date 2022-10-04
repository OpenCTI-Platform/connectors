"""IronNet client"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Iterator, List

import pydantic
import requests
import urllib3.exceptions
from pydantic import BaseModel
from requests import Response

__all__ = [
    "IronNetClient",
    "IronNetItem",
]

log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IronNetClient:
    """IronNet client"""

    def __init__(self, url: str, api_key: str, verify: bool = True):
        """
        Constructor.

        :param url: IronNet url
        :param api_key: IronNet API key
        :param verify: Verify SSL connections
        """

        self._api_url = url
        self._session = requests.Session()
        self._session.headers["x-api-key"] = api_key
        self._session.verify = verify

        if not url:
            raise ValueError("IronNet URL must be set")

        if not api_key:
            raise ValueError("IronNet API key must be set")

    def query(self) -> Iterator[IronNetItem]:
        """
        Process the feed URL and return any indicators.

        :return: Feed results
        """
        resp: Response = self._session.get(self._api_url)
        resp.raise_for_status()

        result_type = Dict[
            str,  # indicator
            Dict[
                str,  # port
                List[IronNetItem],
            ],
        ]
        result = pydantic.parse_raw_as(result_type, resp.text)
        for indicator, ports in result.items():
            for port, entries in ports.items():
                for entry in entries:
                    yield entry


class IronNetItem(BaseModel):
    """Result item"""

    type: str
    indicator: str
    port: int
    last_seen: datetime
    threat: str
    threat_type: str
    confidence: str
    tlp: str
