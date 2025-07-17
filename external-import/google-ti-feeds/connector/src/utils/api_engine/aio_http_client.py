"""AioHttpClient class for making HTTP requests using aiohttp."""

import logging
from asyncio import TimeoutError
from typing import TYPE_CHECKING, Any, Dict, Optional

from aiohttp import (
    ClientConnectorError,
    ClientError,
    ClientSession,
    ClientTimeout,
    ServerConnectionError,
    ServerDisconnectedError,
)

from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_network_error import ApiNetworkError
from .exceptions.api_timeout_error import ApiTimeoutError
from .interfaces.base_http_client import BaseHttpClient

if TYPE_CHECKING:
    from logging import Logger

LOG_PREFIX = "[API AioHttp]"

NETWORK_ERROR_TYPES = (
    ClientConnectorError,
    ServerDisconnectedError,
    ServerConnectionError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionAbortedError,
    ConnectionResetError,
)

NETWORK_ERROR_INDICATORS = [
    "network location cannot be reached",
    "connection refused",
    "cannot connect to host",
    "eof",
    "connection reset",
    "connection timeout",
    "network is unreachable",
    "no route to host",
    "socket.gaierror",
    "dns lookup failed",
]


class AioHttpClient(BaseHttpClient):
    """AioHttpClient class for making HTTP requests using aiohttp.

    This class provides an asynchronous HTTP client implementation using aiohttp.
    It allows making HTTP requests with various parameters such as method, URL, headers, parameters, data, and JSON payload.
    The client supports setting a default timeout for requests and handles exceptions like API errors, HTTP errors, and timeouts.
    """

    def __init__(
        self, default_timeout: int = 60, logger: Optional["Logger"] = None
    ) -> None:
        """Initialize the AioHttpClient with a default timeout  and an optional logger."""
        self.default_timeout = default_timeout
        self._logger = logger or logging.getLogger(__name__)

    @staticmethod
    def _is_network_error(error: Exception) -> bool:
        """Check if an exception represents a network connectivity issue.

        Args:
            error: The exception to check

        Returns:
            bool: True if the exception indicates a network issue, False otherwise

        """
        if isinstance(error, NETWORK_ERROR_TYPES):
            return True

        error_message = str(error).lower()
        return any(indicator in error_message for indicator in NETWORK_ERROR_INDICATORS)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_payload: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Any:
        """Make an asynchronous HTTP request using aiohttp.

        Args:
            method (str): The HTTP method to use.
            url (str): The URL to send the request to.
            headers (Optional[Dict[str, str]], optional): The headers to include in the request. Defaults to None.
            params (Optional[Dict[str, Any]], optional): The query parameters to include in the request. Defaults to None.
            data (Optional[Dict[str, Any]], optional): The data to include in the request body. Defaults to None.
            json_payload (Optional[Dict[str, Any]], optional): The JSON data to include in the request body. Defaults to None.
            timeout (Optional[int], optional): The timeout in seconds for the request. Defaults to None.

        Returns:
            Dict[str, Any]: The JSON response from the server.

        Raises:
            ApiTimeoutError: If the request times out.
            ApiHttpError: If the server returns an HTTP error.
            ApiError: If an unexpected error occurs.

        """
        actual_timeout = ClientTimeout(total=timeout or self.default_timeout)
        self._logger.debug(
            f"{LOG_PREFIX} Making {method} request to {url} with timeout {actual_timeout.total}s. "
            f"Params: {params is not None}, JSON: {json_payload is not None}"
        )
        try:
            async with ClientSession(timeout=actual_timeout, trust_env=True) as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_payload,
                ) as response:
                    self._logger.debug(
                        f"{LOG_PREFIX} Received response with status {response.status} for {method} {url}"
                    )
                    if response.status >= 400:
                        response_text = await response.text()

                        self._logger.error(
                            f"{LOG_PREFIX} HTTP Error {response.status} for {method} {url}: {response_text}",
                        )
                        raise ApiHttpError(response.status, response_text)
                    return await response.json(content_type=None)
        except TimeoutError as e:
            self._logger.error(
                f"{LOG_PREFIX} Request to {url} timed out after {actual_timeout.total}s: {e}",
            )
            raise ApiTimeoutError("Request timed out") from e
        except ClientError as e:
            if self._is_network_error(e):
                self._logger.error(
                    f"{LOG_PREFIX} Network connectivity issue for {method} {url}: {str(e)}",
                )
                raise ApiNetworkError(f"Network connectivity issue: {str(e)}") from e
            else:
                self._logger.error(
                    f"{LOG_PREFIX} ClientError for {url}: {e}",
                )
                raise ApiHttpError(0, str(e)) from e
        except ApiHttpError:
            raise
        except Exception as e:
            if self._is_network_error(e):
                self._logger.error(
                    f"{LOG_PREFIX} Network connectivity issue for {method} {url}: {str(e)}",
                )
                raise ApiNetworkError(f"Network connectivity issue: {str(e)}") from e

            self._logger.error(
                f"{LOG_PREFIX} Unexpected error during request to {url}: {e}",
            )
            raise ApiError(f"Unexpected error: {str(e)}") from e
