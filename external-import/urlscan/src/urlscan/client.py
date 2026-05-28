"""Urlscan client"""

from typing import Iterator, List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from pydantic.v1 import BaseModel, parse_raw_as

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

    def query(self, date_math: str) -> Iterator[str]:
        """Process the feed URL and return any indicators.
        :param date_math: Date math string for the feed.
        :return: Feed results.
        """
        # if date_math already in url, remove it
        parsed_url = urlparse(self._url)
        query_params = parse_qs(parsed_url.query)

        # Update the date_math in the query parameters
        if "q" in query_params:
            query_params["q"] = [f"date:>{date_math}"] + [
                param for param in query_params["q"] if not param.startswith("date:")
            ]
        else:
            query_params["q"] = [f"date:>{date_math}"]

        # Reconstruct the URL with the updated query parameters
        updated_url = urlunparse(
            parsed_url._replace(query=urlencode(query_params, doseq=True))
        )

        resp = requests.get(
            updated_url,
            headers={"API-key": self._api_key},
        )
        resp.raise_for_status()

        parsed = parse_raw_as(UrlscanResponse, resp.text)
        for result in parsed.results:
            yield result.page_url


class UrlscanResult(BaseModel):
    """Urlscan result"""

    page_url: str


class UrlscanResponse(BaseModel):
    """Urlscan response"""

    results: List[UrlscanResult]
