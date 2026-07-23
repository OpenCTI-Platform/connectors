"""Base HTTP API client for OpenCTI connectors.

Provides a reusable foundation that handles:
- Session management with connection pooling (lazy initialization)
- Common authentication patterns (header-based API keys, Bearer tokens)
- Structured error handling with typed exceptions
- Automatic retries with exponential backoff (429, 5xx) via urllib3
- Proactive rate limiting via the ``limits`` library
- Pagination helpers (offset/page-based)
- Configurable timeouts and SSL verification
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Any, Callable
from urllib.parse import urljoin

import requests
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from connectors_sdk.client.rate_limit import RateLimit, _RateLimitAdapter
from requests.adapters import Retry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base client
# ---------------------------------------------------------------------------


class BaseClientApi:
    """Base HTTP client providing common API interaction patterns.

    Subclass this to create a connector-specific client. Override
    ``session_headers`` to provide authentication headers.

    Example::

        class MyClient(BaseClientApi):
            def __init__(self, base_url: str, api_key: str) -> None:
                super().__init__(base_url)
                self._api_key = api_key

            @property
            def session_headers(self) -> dict[str, str]:
                return {"Authorization": f"Bearer {self._api_key}"}

            def get_indicators(self, page: int = 1) -> dict:
                return self._get("/api/indicators", params={"page": page})

    Args:
        base_url: Base URL of the API (trailing slash is stripped).
        timeout: Default request timeout in seconds.
        ssl_verify: Whether to verify SSL certificates.
        max_retries: Maximum number of retries for transient errors (408, 429, 5xx).
        backoff_factor: Multiplier for exponential backoff between retries.
        rate_limit: Rate limit as a :class:`RateLimit` instance (e.g.
            ``RateLimit(100, "minute")``) or a raw ``limits`` string
            (e.g. ``"100/minute"``). ``None`` to disable.
        raise_on_limit_exceeded: If True (default), raises ``ApiRateLimitError``
            when the proactive rate limit is exceeded. If False, the client
            will sleep until the window resets.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        rate_limit: RateLimit | str | None = None,
        raise_on_limit_exceeded: bool = True,
    ) -> None:
        """Initialize the API client.

        See class docstring for parameter descriptions.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._ssl_verify = ssl_verify
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._rate_limit = rate_limit
        self._raise_on_limit_exceeded = raise_on_limit_exceeded
        self.__session: requests.Session | None = None

    # ------------------------------------------------------------------
    # Session (lazy initialization)
    # ------------------------------------------------------------------

    @property
    def _session(self) -> requests.Session:
        """Return the requests session, creating it on first access.

        The session is configured with retry strategy, rate limiting,
        SSL settings, and headers. Lazy initialization avoids allocating
        resources if the client is never used.
        """
        if self.__session is None:
            self.__session = requests.Session()
            self.__session.verify = self._ssl_verify
            self.__session.headers.update({"Accept": "application/json"})
            self.__session.headers.update(self.session_headers)

            # Retry on transient errors with exponential backoff
            retry_strategy = Retry(
                total=self._max_retries,
                backoff_factor=self._backoff_factor,
                status_forcelist=[408, 429, 500, 502, 503, 504],
                respect_retry_after_header=True,
                raise_on_status=False,
            )

            adapter = _RateLimitAdapter(
                rate_limit=self._rate_limit,
                rate_limit_key=self._base_url,
                raise_on_limit_exceeded=self._raise_on_limit_exceeded,
                max_retries=retry_strategy,
            )
            self.__session.mount("https://", adapter)
            self.__session.mount("http://", adapter)

        return self.__session

    # ------------------------------------------------------------------
    # Public HTTP methods
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Perform a GET request.

        Args:
            path: API endpoint path.
            params: Query parameters.
            **kwargs: Additional arguments forwarded to the session.

        Returns:
            Parsed response body (JSON dict/list, str, or bytes depending
            on Content-Type).

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

        Args:
            path: API endpoint path.
            json: JSON-serializable body.
            data: Form-encoded or raw body.
            params: Query parameters.
            **kwargs: Additional arguments forwarded to the session.

        Returns:
            Parsed response body, or ``requests.Response`` when ``stream=True``.

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
    # Pagination helpers
    # ------------------------------------------------------------------

    def _paginate_offset(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        page_param: str = "page",
        page_size_param: str = "per_page",
        page_size: int = 100,
        start_page: int = 1,
        results_extractor: str | Callable[[Any], list[Any]] | None = None,
    ) -> Generator[list[Any], None, None]:
        """Iterate through offset/page-based pagination.

        Yields pages of results until an empty page or a page smaller than
        ``page_size`` is received.

        Args:
            path: API endpoint path.
            params: Additional query parameters.
            page_param: Name of the page number parameter.
            page_size_param: Name of the page size parameter.
            page_size: Number of results per page.
            start_page: First page number (usually 0 or 1).
            results_extractor: How to extract results from the response.
                         - ``None``: the response itself is used as the results list.
                         - ``str``: key to look up in the response dict.
                         - ``Callable``: called with the response, must return a list.

        Yields:
            Lists of result items, one per page.
        """
        current_page = start_page
        base_params = dict(params) if params else {}

        while True:
            page_params = {
                **base_params,
                page_param: current_page,
                page_size_param: page_size,
            }
            response = self._get(path, params=page_params)

            if callable(results_extractor):
                results = results_extractor(response)
            elif results_extractor:
                results = response[results_extractor]
            else:
                results = response

            if not results:
                break

            yield results

            if len(results) < page_size:
                break
            current_page += 1

    # ------------------------------------------------------------------
    # Core request handling
    # ------------------------------------------------------------------

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Perform a raw HTTP request and return the Response object unchanged.

        Retries and rate limiting are handled by the underlying adapter/urllib3.
        No response parsing or error raising is done here.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: URL path relative to ``base_url``.
            **kwargs: Passed to ``requests.Session.request()``.

        Returns:
            The raw ``requests.Response`` object.
        """
        url = self._build_url(path)
        kwargs.setdefault("timeout", self._timeout)
        return self._session.request(method, url, **kwargs)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute an HTTP request with error handling and response parsing.

        Delegates the actual HTTP call to ``_raw_request``, then raises typed
        exceptions for non-retryable errors and parses the body.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: URL path relative to ``base_url``.
            **kwargs: Passed to ``requests.Session.request()``.

        Returns:
            Parsed response body or None for 204.

        Raises:
            ApiUnauthorizedError: On 401.
            ApiForbiddenError: On 403.
            ApiNotFoundError: On 404.
            ApiRateLimitError: On 429 after retries exhausted.
            ApiServerError: On 5xx after retries exhausted.
            ApiClientError: On other HTTP errors.
        """
        response = self._raw_request(method, path, **kwargs)

        if response.status_code == 204:
            return None

        if not response.ok:
            self._raise_for_status(response, method, path)

        return self._parse_response(response)

    # ------------------------------------------------------------------
    # Hooks for subclasses
    # ------------------------------------------------------------------

    @property
    def session_headers(self) -> dict[str, str]:
        """Return additional headers applied during session initialization.

        Override this in subclasses to provide static headers that are set
        once when the session is created. These headers persist for the
        lifetime of the session and are **not** refreshed on each request.

        For dynamic authentication (e.g. token refresh), override
        ``_raw_request`` to inject headers per-request instead.

        Returns:
            A dictionary of HTTP headers.
        """
        return {}

    def _parse_response(self, response: requests.Response) -> Any:
        """Parse a successful response based on Content-Type.

        Override this in subclasses to customize response handling.

        Default behavior:
        - ``application/json`` → parsed JSON (dict/list)
        - ``text/*`` → ``response.text`` (str)
        - everything else (zip, pdf, image…) → ``response.content`` (bytes)
        - no Content-Type: attempts JSON, falls back to text
        """
        content_type = response.headers.get("Content-Type", "").lower()

        if "application/json" in content_type:
            return response.json()

        if content_type.startswith("text/"):
            return response.text or None

        if not content_type and response.text:
            # No Content-Type header — try JSON, fall back to text
            try:
                return response.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                return response.text

        # Binary content (zip, pdf, image, octet-stream, …)
        if content_type:
            return response.content

        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_url(self, path: str) -> str:
        """Build full URL from base and path.

        Note: If ``path`` is an absolute URL (starts with a scheme like
        ``https://``), it will be returned as-is due to ``urljoin`` semantics.
        """
        return urljoin(self._base_url + "/", path.lstrip("/"))

    def _raise_for_status(
        self, response: requests.Response, method: str, path: str
    ) -> None:
        """Raise typed exceptions based on status code."""
        body = self._safe_response_body(response)
        status = response.status_code

        if status == 401:
            raise ApiUnauthorizedError(
                f"Unauthorized (401) on {method} {path}",
                response_body=body,
            )
        if status == 403:
            raise ApiForbiddenError(
                f"Forbidden (403) on {method} {path}",
                response_body=body,
            )
        if status == 404:
            raise ApiNotFoundError(
                f"Not found (404) on {method} {path}",
                response_body=body,
            )
        if status == 429:
            retry_after = ApiRateLimitError.parse_retry_after(response.headers)
            raise ApiRateLimitError(
                f"Rate limited (429) on {method} {path}",
                response_body=body,
                retry_after=retry_after,
            )
        if status >= 500:
            raise ApiServerError(
                f"Server error ({status}) on {method} {path}",
                status_code=status,
                response_body=body,
            )
        raise ApiClientError(
            f"HTTP {status} on {method} {path}",
            status_code=status,
            response_body=body,
        )

    @staticmethod
    def _safe_response_body(response: requests.Response) -> Any:
        """Try to extract JSON body, fall back to text."""
        try:
            return response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            if not response.text:
                return None
            if len(response.text) > 2000:
                return response.text[:2000] + "...[truncated]"
            return response.text
