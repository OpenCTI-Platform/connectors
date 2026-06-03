"""Base HTTP API client for OpenCTI connectors.

Provides a reusable foundation that handles:
- Session management with connection pooling
- Common authentication patterns (header-based API keys, Bearer tokens)
- Structured error handling with typed exceptions
- Automatic retries with exponential backoff (429, 5xx)
- Pagination helpers (offset-based and cursor-based)
- Configurable timeouts and SSL verification
"""

from __future__ import annotations

from abc import ABC
import logging
from datetime import timedelta
from collections.abc import Generator
from typing import Any, Callable, ClassVar
from urllib.parse import urljoin

from pydantic import HttpUrl
import requests
from connectors_sdk.http_client.exceptions import (
    HttpClientException,
    HttpRequestClientError,
    HttpRequestError,
    HttpRequestServerError,
)
from connectors_sdk.http_client.http_adapter import RateLimitHTTPAdapter, RateLimit
from requests.adapters import Retry

DEFAULT_HEADERS = {"Accept": "application/json"}


class BaseHttpClient(ABC):
    """Base HTTP client providing common API interaction patterns.

    Subclass this to create a connector-specific client.
    For more advanced behavior, override `__init__` in order to customize the arguments (e.g.,
    add API token, username/password or common params), the request or
    session handling in a subclass.

    Example::

        class MyClient(BaseHttpClient):
            def __init__(self, base_url: str, api_key: str) -> None:
                super().__init__(base_url, headers={"X-API-KEY": api_key})

            def get_indicators(self, page: int = 1) -> dict:
                return self._get("/api/indicators", params={"page": page})

    Args:
        base_url: Base URL of the API (trailing slash is stripped).
        ssl_verify: Whether to verify SSL certificates.
        timeout: Default request timeout in seconds.
        rate_limit: Maximum number of requests per interval (0 to disable).
        rate_interval: Minimum amount of time between consecutive requests (0 to disable).
        max_retries: Maximum number of retries for transient errors.
        backoff_factor: Multiplier for exponential backoff between retries.
    """

    logger: ClassVar[logging.Logger] = logging.getLogger("BaseHttpClient")

    __session: requests.Session | None = None

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        cls.logger = logging.getLogger(cls.__name__)

    def __init__(
        self,
        base_url: HttpUrl | str,
        ssl_verify: bool = True,
        timeout: int = 60,
        rate_limit: int = 0,
        rate_interval: timedelta = timedelta(seconds=0),
        max_retries: int = 3,
        backoff_factor: float = 1.0,
    ) -> None:
        """Initialize the HTTP client.

        See class docstring for parameter descriptions.
        """
        self._base_url = str(base_url)
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._rate_limit = rate_limit
        self._rate_interval = rate_interval
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor

    @property
    def _session(self) -> requests.Session:
        """Return the `requests.Session` object based on the HTTP client's configuration.

        A session is lazy-initialized on first request (see `_raw_request`), and reused for
        subsequent requests to take advantage of connection pooling.
        Session's headers can be customized by overriding the `session_headers` property in subclasses.

        Returns:
            A `requests.Session` object with session_headers set.
        """
        if self.__session is None:
            self.__session = requests.Session()
            self.__session.verify = self._ssl_verify
            self.__session.headers.update(DEFAULT_HEADERS)
            self.__session.headers.update(self.session_headers)

            # Set up rate limit for every requests (including retries)
            rate_limit = RateLimit(
                url=self._base_url,
                rate_limit=self._rate_limit,
                rate_interval=self._rate_interval,
            )

            # Retry only idempotent requests that may succeed as-is on next try
            retry_strategy = Retry(
                total=self._max_retries,
                backoff_factor=self._backoff_factor,
                status_forcelist=[
                    408,  # Request Timeout
                    409,  # Conflict
                    429,  # Too Many Requests
                    500,  # Internal Server Error
                    502,  # Bad Gateway
                    503,  # Service Unavailable
                    504,  # Gateway Timeout
                ],
                respect_retry_after_header=True,
                raise_on_status=False,  # use response.raise_for_status() instead
            )

            http_adapter = RateLimitHTTPAdapter(
                rate_limit=rate_limit,
                max_retries=retry_strategy,
            )
            self.__session.mount("https://", http_adapter)
            self.__session.mount("http://", http_adapter)

        return self.__session

    # ------------------------------------------------------------------
    # Hooks for subclasses
    # ------------------------------------------------------------------

    @property
    def session_headers(self) -> dict[str, str]:
        """Return common headers to include in every request.

        Override this method in subclasses to provide dynamic headers (e.g. for
        token refresh). The returned headers will be merged with any headers
        passed directly to the request methods, with request-specific headers
        taking precedence.

        Returns:
            A dictionary of HTTP headers.
        """
        return {}

    def _parse_response_body(self, response: requests.Response) -> Any:
        """Parse a response's body. Override for non-JSON APIs."""
        if response.status_code == 204:
            return None

        content_type = response.headers.get("Content-Type", "").lower()
        if content_type == "application/json":
            return response.json()

        return response.text

    # ------------------------------------------------------------------
    # Private HTTP methods
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a GET request.

        Returns:
            Parsed JSON response body.

        Raises:
            ApiClientError: On HTTP errors.
        """
        return self._request("GET", path, params=params, **kwargs)

    def _post(
        self,
        path: str,
        *,
        json: Any | None = None,
        data: Any | None = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a POST request.

        Returns:
            Parsed JSON response body.

        Raises:
            ApiClientError: On HTTP errors.
        """
        return self._request(
            "POST", path, json=json, data=data, params=params, **kwargs
        )

    def _put(
        self,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a PUT request."""
        return self._request("PUT", path, json=json, params=params, **kwargs)

    def _patch(
        self,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a PATCH request."""
        return self._request("PATCH", path, json=json, params=params, **kwargs)

    def _delete(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a DELETE request."""
        return self._request("DELETE", path, params=params, **kwargs)

    # ------------------------------------------------------------------
    # Core request handling
    # ------------------------------------------------------------------

    def _parse_error_response_body(self, response: requests.Response) -> Any:
        """Try to extract response's body, fall back to text.
        Used for error handling when response body may not be JSON or may be too large.
        """
        try:
            return self._parse_response_body(response)
        except (ValueError, requests.exceptions.JSONDecodeError):
            return response.text[:2000] if response.text else None

    def _raw_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> requests.Response:
        """Perform a raw HTTP request and return the Response object.

        This method bypasses response's parsing, i.e., returns the raw Response.
        It still applies error handling and retries.
        Use _request() for automatic response's parsing.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: URL path relative to base_url.
            **kwargs: Passed to ``requests.Session.request()``.

        Returns:
            The raw ``requests.Response`` object.

        Raises:
            HttpRequestServerError: On HTTP response with a 5xx status code.
            HttpRequestClientError: On HTTP response with a 4xx status code.
            HttpRequestError: On HTTP errors before receiving any response.
            HttpClientRateLimitError: If rate limit is exceeded and retries are exhausted.
            HttpClientException: For other unexpected errors.
        """
        url = BaseHttpClient._resolve_url(self._base_url, endpoint)

        try:
            kwargs.setdefault("timeout", self._timeout)

            # Init a `requests.Session` on first request (see `_session` property)
            response = self._session.request(method, url, **kwargs)
            response.raise_for_status()

            return response
        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                status_code = e.response.status_code
                response_body = self._parse_error_response_body(e.response)

                if status_code > 500:
                    raise HttpRequestServerError(
                        f"Server error ({status_code}) on {method} {endpoint}",
                        status_code,
                        response_body,
                    ) from e
                if status_code >= 400:
                    raise HttpRequestClientError(
                        f"Client error ({status_code}) on {method} {endpoint}",
                        status_code,
                        response_body,
                    ) from e

                raise HttpRequestError(
                    f"HTTP error ({status_code}) on {method} {endpoint}",
                    status_code,
                    response_body,
                ) from e

            if e.request is not None:
                raise HttpRequestError(
                    f"HTTP error with no response on {method} {endpoint}: {str(e)}"
                ) from e

            raise HttpClientException(
                f"Unexpected HTTP error on {method} {endpoint}: {str(e)}"
            ) from e

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        """Execute an HTTP request with rate limiting, response parsing, and error handling.

        Handles 429 rate-limit responses with automatic backoff/retry.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: URL path relative to base_url.
            **kwargs: Passed to ``requests.Session.request()``.

        Returns:
            Parsed request's response (or `None` for `204 - No Content`).

        Raises:
            HttpRequestServerError: On HTTP response with a 5xx status code.
            HttpRequestClientError: On HTTP response with a 4xx status code.
            HttpRequestError: On HTTP errors before receiving any response.
            HttpClientRateLimitError: If rate limit is exceeded and retries are exhausted.
            HttpClientException: For other unexpected errors.

        """
        response = self._raw_request(method, endpoint, **kwargs)
        return self._parse_response_body(response)

    # # ------------------------------------------------------------------
    # # Pagination helpers
    # # ------------------------------------------------------------------

    # def _paginate_offset(
    #     self,
    #     path: str,
    #     *,
    #     params: dict[str, Any] | None = None,
    #     page_param: str = "page",
    #     page_size_param: str = "per_page",
    #     page_size: int = 100,
    #     start_page: int = 1,
    #     results_key: str | None = None,
    # ) -> Generator[list[Any], None, None]:
    #     """Iterate through offset/page-based pagination.

    #     Yields pages of results until an empty page or a page smaller than
    #     ``page_size`` is received.

    #     Args:
    #         path: API endpoint path.
    #         params: Additional query parameters.
    #         page_param: Name of the page number parameter.
    #         page_size_param: Name of the page size parameter.
    #         page_size: Number of results per page.
    #         start_page: First page number (usually 0 or 1).
    #         results_key: If the response is a dict, extract results from this key.
    #                      If None, the response itself is treated as the results list.

    #     Yields:
    #         Lists of result items, one per page.
    #     """
    #     current_page = start_page
    #     base_params = dict(params) if params else {}

    #     while True:
    #         page_params = {
    #             **base_params,
    #             page_param: current_page,
    #             page_size_param: page_size,
    #         }
    #         response = self._get(path, params=page_params)

    #         results = response[results_key] if results_key else response
    #         if not results:
    #             break

    #         yield results

    #         if len(results) < page_size:
    #             break
    #         current_page += 1

    # def _paginate_cursor(
    #     self,
    #     path: str,
    #     *,
    #     params: dict[str, Any] | None = None,
    #     cursor_param: str = "cursor",
    #     cursor_extractor: Callable[[Any], str | None] | None = None,
    #     results_key: str | None = None,
    # ) -> Generator[list[Any], None, None]:
    #     """Iterate through cursor-based pagination.

    #     Yields pages of results until no next cursor is returned.

    #     Args:
    #         path: API endpoint path.
    #         params: Additional query parameters.
    #         cursor_param: Name of the cursor parameter to send.
    #         cursor_extractor: Function to extract the next cursor from the response.
    #                           If None, looks for ``response["next"]`` or
    #                           ``response["meta"]["next_cursor"]``.
    #         results_key: If the response is a dict, extract results from this key.
    #                      If None and response is a dict with a ``results_key``,
    #                      falls back to ``"data"`` or ``"results"``.

    #     Yields:
    #         Lists of result items, one per page.
    #     """
    #     base_params = dict(params) if params else {}
    #     cursor: str | None = None

    #     while True:
    #         page_params = {**base_params}
    #         if cursor:
    #             page_params[cursor_param] = cursor

    #         response = self._get(path, params=page_params)

    #         results = self._extract_results(response, results_key)
    #         if not results:
    #             break

    #         yield results

    #         # Extract next cursor
    #         if cursor_extractor:
    #             cursor = cursor_extractor(response)
    #         elif isinstance(response, dict):
    #             cursor = response.get("next") or (
    #                 response.get("meta", {}).get("next_cursor")
    #             )
    #         else:
    #             cursor = None

    #         if not cursor:
    #             break

    # def _paginate_links(
    #     self,
    #     path: str,
    #     *,
    #     params: dict[str, Any] | None = None,
    #     next_url_extractor: Callable[[Any], str | None] | None = None,
    #     results_key: str | None = None,
    # ) -> Generator[list[Any], None, None]:
    #     """Iterate through link-based (HATEOAS) pagination.

    #     Follows a "next" URL returned in the response body until no more
    #     pages are available.

    #     Args:
    #         path: Initial API endpoint path.
    #         params: Query parameters for the first request only.
    #         next_url_extractor: Function to extract the next URL from the response.
    #                             If None, looks for ``response["_links"]["next"]["href"]``
    #                             or ``response["next_url"]``.
    #         results_key: If the response is a dict, extract results from this key.
    #                      If None, tries ``"items"`` or ``"data"``.

    #     Yields:
    #         Lists of result items, one per page.
    #     """
    #     url: str | None = None

    #     while True:
    #         if url is None:
    #             response = self._get(path, params=params)
    #         else:
    #             # Resolve relative URLs against the base URL
    #             resolved_url = urljoin(self._base_url + "/", url)
    #             response = self._request("GET", resolved_url, _absolute_url=True)

    #         results = self._extract_results(response, results_key)
    #         if not results:
    #             break

    #         yield results

    #         # Extract next URL
    #         if next_url_extractor:
    #             url = next_url_extractor(response)
    #         elif isinstance(response, dict):
    #             links = response.get("_links", {})
    #             next_link = links.get("next", {})
    #             url = next_link.get("href") if next_link else None
    #             if not url:
    #                 url = response.get("next_url")
    #         else:
    #             url = None

    #         if not url:
    #             break

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_url(url: str, *args: str) -> str:
        """Resolve full URL from given URL and optional path segments.

        Arguments:
            url: Base URL.
            *args: Additional path segments to append to the URL.

        Returns:
            Full URL string.
        """
        path = "/".join(arg.strip("/") for arg in args)
        return urljoin(url + "/", path)
