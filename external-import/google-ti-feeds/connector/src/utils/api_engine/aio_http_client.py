"""AioHttpClient class for making HTTP requests using aiohttp."""

from asyncio import TimeoutError
from typing import Any, Dict, Optional

from aiohttp import ClientError, ClientSession, ClientTimeout

from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_timeout_error import ApiTimeoutError
from .interfaces.base_http_client import BaseHttpClient


class AioHttpClient(BaseHttpClient):
    """AioHttpClient class for making HTTP requests using aiohttp.

    This class provides an asynchronous HTTP client implementation using aiohttp.
    It allows making HTTP requests with various parameters such as method, URL, headers, parameters, data, and JSON payload.
    The client supports setting a default timeout for requests and handles exceptions like API errors, HTTP errors, and timeouts.
    """

    def __init__(self, default_timeout: int = 60) -> None:
        """Initialize the AioHttpClient with a default timeout."""
        self.default_timeout = default_timeout

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

        try:
            async with ClientSession(timeout=actual_timeout) as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_payload,
                ) as response:
                    if response.status >= 400:
                        raise ApiHttpError(response.status, await response.text())
                    return await response.json()
        except TimeoutError as e:
            raise ApiTimeoutError("Request timed out") from e
        except ClientError as e:
            raise ApiHttpError(0, str(e)) from e
        except Exception as e:
            raise ApiError(f"Unexpected error: {str(e)}") from e
