"""Offer common tools for the TAP API."""

from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import aiohttp


class BaseTAPClient:
    """Base class for the TAP API client."""

    def __init__(self, base_url: str, principal: str, secret: str) -> None:
        """Initialize the client.

        Args:
            base_url (str): The base URL of the TAP API.
            principal (str): The principal to authenticate with the API.
            secret (str): The secret to authenticate with the API.

        """
        scheme, netloc, _, _, _, _ = urlparse(base_url)
        self.base_url_scheme = scheme
        self.base_url_netloc = netloc
        self.auth = aiohttp.BasicAuth(principal, secret)

    def format_get_query(self, path: str, query: dict[str, Any] | None = None) -> str:
        """Format a query URL.

        Args:
            path (str): The path of the URL.
            query (dict): The query parameters.

        Returns:
            str: The formatted URL.

        """
        return urlunparse(
            (
                self.base_url_scheme,  # scheme
                self.base_url_netloc,  # netloc
                path,  # path
                "",  # params
                urlencode(query) if query is not None else "",  # query
                "",  # fragment
            )
        )
