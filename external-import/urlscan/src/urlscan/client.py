"""Urlscan client"""

from typing import Iterator, List

import pydantic
import requests
from pydantic import BaseModel

__all__ = [
    "UrlscanClient",
]


class UrlscanClient:
    """Urlscan.io client"""

    def __init__(self, url: str, api_key: str):
        """Initializer.
        :param url: Urlscan URL
        :param api_key: Urlscan api key
        """
        self._url = url
        self._api_key = api_key

        if not url:
            raise ValueError("Urlscan URL must be set")

        if not api_key:
            raise ValueError("Urlscan API key must be set")

    def query(self) -> Iterator[str]:
        """Process the feed URL and return any indicators.
        :return: Feed results.
        """
        resp = requests.get(
            self._url,
            headers={"API-key": self._api_key},
        )
        resp.raise_for_status()

        parsed = pydantic.parse_raw_as(UrlscanResponse, resp.text)
        for result in parsed.results:
            yield result.page_url


class UrlscanResult(BaseModel):
    """Urlscan result"""

    page_url: str


class UrlscanResponse(BaseModel):
    """Urlscan response"""

    results: List[UrlscanResult]
