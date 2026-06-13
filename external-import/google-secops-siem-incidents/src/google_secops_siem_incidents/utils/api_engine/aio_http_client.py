"""Async HTTP client backed by aiohttp."""

import asyncio
from typing import Any

import aiohttp

from .exceptions import (
    ApiError,
    ApiHttpError,
    ApiNetworkError,
    ApiRateLimitError,
    ApiTimeoutError,
)
from .interfaces.base_http_client import BaseHttpClient

_NETWORK_ERROR_STRINGS = ("connection", "resolve", "unreachable", "refused", "reset")


def _is_network_error(exc: Exception) -> bool:
    """Return True if the exception represents a network connectivity failure.

    Args:
        exc: Exception to inspect.

    Returns:
        True if the exception is classified as a network error.
    """
    if isinstance(
        exc,
        (
            aiohttp.ClientConnectorError,
            aiohttp.ServerDisconnectedError,
            aiohttp.ClientConnectionError,
        ),
    ):
        return True
    msg = str(exc).lower()
    return any(s in msg for s in _NETWORK_ERROR_STRINGS)


class AioHttpClient(BaseHttpClient):
    """Concrete async HTTP client using aiohttp."""

    def __init__(self, default_timeout: int = 30) -> None:
        """Initialise with default timeout of *default_timeout* seconds.

        Args:
            default_timeout: Request timeout in seconds.
        """
        self.default_timeout = default_timeout
        self._session: aiohttp.ClientSession | None = None

    def _get_session(self) -> aiohttp.ClientSession:
        """Return the shared session, creating it on first use.

        Returns:
            Active aiohttp.ClientSession instance.
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

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
        """Send an HTTP request and return the parsed JSON body.

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

        Raises:
            ApiRateLimitError: On HTTP 429 response.
            ApiHttpError: On any other HTTP 4xx/5xx response.
            ApiTimeoutError: When the request exceeds the timeout.
            ApiNetworkError: On network connectivity failure.
        """
        effective_timeout = aiohttp.ClientTimeout(
            total=timeout if timeout is not None else self.default_timeout
        )
        session = self._get_session()
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_payload,
                timeout=effective_timeout,
            ) as response:
                if response.status == 429:
                    text = await response.text()
                    raise ApiRateLimitError(f"Rate limit exceeded: HTTP 429 — {text}")
                if response.status >= 400:
                    text = await response.text()
                    raise ApiHttpError(text, status_code=response.status)
                return await response.json()
        except (ApiHttpError, ApiRateLimitError):
            raise
        except (asyncio.TimeoutError, aiohttp.ServerTimeoutError) as exc:
            raise ApiTimeoutError("Request timed out") from exc
        except Exception as exc:
            if _is_network_error(exc):
                raise ApiNetworkError(str(exc)) from exc
            # Preserve the typed-error boundary: wrap anything unexpected
            # (e.g. JSON-decode / content-type errors) in ApiError so callers
            # never see raw aiohttp/stdlib exceptions leak out.
            raise ApiError(str(exc)) from exc
