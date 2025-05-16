"""AioHttpClient class for making HTTP requests using aiohttp."""

import logging
from asyncio import TimeoutError
from typing import TYPE_CHECKING, Any, Dict, Optional

from aiohttp import ClientError, ClientSession, ClientTimeout

from .exceptions.api_error import ApiError
from .exceptions.api_http_error import ApiHttpError
from .exceptions.api_timeout_error import ApiTimeoutError
from .interfaces.base_http_client import BaseHttpClient

if TYPE_CHECKING:
    from logging import Logger


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
            f"[API Client] Making {method} request to {url} with timeout {actual_timeout.total}s. "
            f"Params: {params is not None}, JSON: {json_payload is not None}"
        )
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
                    self._logger.debug(
                        f"[API Client] Received response with status {response.status} for {method} {url}"
                    )
                    if response.status >= 400:
                        response_text = await response.text()
                        self._logger.error(  # type: ignore[call-arg]
                            f"[API Client] HTTP Error {response.status} for {method} {url}: {response_text}",
                            meta={"error": response_text},
                        )
                        raise ApiHttpError(response.status, response_text)
                    return await response.json()
        except TimeoutError as e:
            self._logger.error(f"[API Client] Request to {url} timed out after {actual_timeout.total}s: {e}", meta={"error": str(e)})  # type: ignore[call-arg]
            raise ApiTimeoutError("Request timed out") from e
        except ClientError as e:
            self._logger.error(f"[API Client] ClientError for {url}: {e}", meta={"error": str(e)})  # type: ignore[call-arg]
            raise ApiHttpError(0, str(e)) from e
        except ApiHttpError:
            raise
        except Exception as e:
            self._logger.error(f"[API Client] Unexpected error during request to {url}: {e}", meta={"error": str(e)})  # type: ignore[call-arg]
            raise ApiError(f"Unexpected error: {str(e)}") from e
