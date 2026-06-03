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
from collections.abc import Generator
from typing import Any, Callable, ClassVar, Literal
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

    Attributes:
        logger: Logger instance for the class.
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
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        rate_limit: int | None = None,
        rate_expiry: (
            tuple[
                int,
                Literal[
                    "day",
                    "month",
                    "year",
                    "hour",
                    "minute",
                    "second",
                ],
            ]
            | None
        ) = None,
    ) -> None:
        """Initialize the HTTP client.

        Args:
            base_url: Base URL of the API.
            ssl_verify: Whether to verify SSL certificates.
            timeout: Default request timeout in seconds.
            max_retries: Maximum number of retries for transient errors.
            backoff_factor: Multiplier for exponential backoff between retries.
            rate_limit: Maximum number of requests per interval (`None` to disable).
            rate_expiry: Time window for the rate limit, expressed in multiple of time units
            e.g., `(2, "hour")` for a rate limit that expires every 2 hours (`None` to disable).
        """
        self._base_url = str(base_url)
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._rate_limit = rate_limit
        self._rate_expiry = rate_expiry

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
                rate_expiry=self._rate_expiry,
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


# Decorators


def paginate_offset(
    page_param: str = "page",
    start_page: int = 1,
    page_size_param: str = "page_size",
    page_size: int = 100,
    result_extractor: Callable[[Any], Any] | None = None,
) -> Callable[..., Generator[Any, None, None]]:

    def paginate(
        request_fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Generator[list[Any], None, None]:
        base_params = kwargs.get("params", {})

        current_page = start_page
        while True:
            page_params = {
                **base_params,
                page_param: current_page,
                page_size_param: page_size,
            }
            kwargs["params"] = page_params

            data = request_fn(*args, **kwargs)
            if not data:
                break

            results = result_extractor(data) if result_extractor else data

            yield results

            if len(results) < page_size:
                break

            current_page += 1

    return paginate
