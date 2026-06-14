"""Base HTTP client interface."""

from abc import ABC, abstractmethod
from typing import Any


class BaseHttpClient(ABC):
    """Abstract async HTTP client."""

    @abstractmethod
    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_payload: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Send an HTTP request and return the parsed response.

        Args:
            method: HTTP method (e.g. 'GET', 'POST').
            url: Target URL.
            headers: Optional request headers.
            params: Optional query parameters.
            data: Optional form data payload.
            json_payload: Optional JSON body payload.
            timeout: Override timeout in seconds.

        Returns:
            Parsed JSON response as a dict.
        """
        ...
