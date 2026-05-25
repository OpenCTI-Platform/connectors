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

import logging
import time
from collections.abc import Generator
from typing import Any, Callable
from urllib.parse import urljoin

import requests
from connectors_sdk.client.exceptions import (
    ApiClientError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)


class BaseClientApi:
    """Base HTTP client providing common API interaction patterns.

    Subclass this to create a connector-specific client. For common
    authentication schemes, pass default ``headers`` or ``auth`` to
    ``__init__``. For more advanced behavior, override the request or
    session handling in a subclass.

    Example::

        class MyClient(BaseClientApi):
            def __init__(self, base_url: str, api_key: str) -> None:
                super().__init__(base_url, headers={"X-API-KEY": api_key})

            def get_indicators(self, page: int = 1) -> dict:
                return self._get("/api/indicators", params={"page": page})

    Args:
        base_url: Base URL of the API (trailing slash is stripped).
        headers: Default headers to include in every request.
        auth: Tuple of (username, password) for HTTP Basic Auth.
        timeout: Default request timeout in seconds.
        ssl_verify: Whether to verify SSL certificates.
        max_retries: Maximum number of retries for transient errors.
        backoff_factor: Multiplier for exponential backoff between retries.
        rate_limit_interval: Minimum seconds between consecutive requests (0 to disable).
    """

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        rate_limit_interval: float = 0,
    ) -> None:
        """Initialize the API client.

        See class docstring for parameter descriptions.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._ssl_verify = ssl_verify
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._rate_limit_interval = rate_limit_interval
        self._last_request_time: float = 0

        self._session = requests.Session()
        self._session.verify = ssl_verify
        self._session.headers.update({"Accept": "application/json"})
        if headers:
            self._session.headers.update(headers)
        if auth:
            self._session.auth = auth

        # Disable urllib3 automatic retries — all retry logic is handled
        # explicitly in _request() with proper logging and backoff.
        adapter = HTTPAdapter(max_retries=0)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

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

    def _get_raw(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a GET request and return the raw Response object.

        Use this for binary downloads, streaming, or non-JSON responses.
        Error handling (status codes, retries) still applies.

        Args:
            path: API endpoint path.
            params: Query parameters.
            stream: If True, response body is not immediately downloaded.
            **kwargs: Additional keyword arguments passed to the underlying request.

        Returns:
            The raw ``requests.Response`` object.
        """
        return self._request(
            "GET", path, params=params, stream=stream, _raw=True, **kwargs
        )

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
        results_key: str | None = None,
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
            results_key: If the response is a dict, extract results from this key.
                         If None, the response itself is treated as the results list.

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

            results = response[results_key] if results_key else response
            if not results:
                break

            yield results

            if len(results) < page_size:
                break
            current_page += 1

    def _paginate_cursor(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        cursor_param: str = "cursor",
        cursor_extractor: Callable[[Any], str | None] | None = None,
        results_key: str | None = None,
    ) -> Generator[list[Any], None, None]:
        """Iterate through cursor-based pagination.

        Yields pages of results until no next cursor is returned.

        Args:
            path: API endpoint path.
            params: Additional query parameters.
            cursor_param: Name of the cursor parameter to send.
            cursor_extractor: Function to extract the next cursor from the response.
                              If None, looks for ``response["next"]`` or
                              ``response["meta"]["next_cursor"]``.
            results_key: If the response is a dict, extract results from this key.
                         If None and response is a dict with a ``results_key``,
                         falls back to ``"data"`` or ``"results"``.

        Yields:
            Lists of result items, one per page.
        """
        base_params = dict(params) if params else {}
        cursor: str | None = None

        while True:
            page_params = {**base_params}
            if cursor:
                page_params[cursor_param] = cursor

            response = self._get(path, params=page_params)

            results = self._extract_results(response, results_key)
            if not results:
                break

            yield results

            # Extract next cursor
            if cursor_extractor:
                cursor = cursor_extractor(response)
            elif isinstance(response, dict):
                cursor = response.get("next") or (
                    response.get("meta", {}).get("next_cursor")
                )
            else:
                cursor = None

            if not cursor:
                break

    def _paginate_links(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        next_url_extractor: Callable[[Any], str | None] | None = None,
        results_key: str | None = None,
    ) -> Generator[list[Any], None, None]:
        """Iterate through link-based (HATEOAS) pagination.

        Follows a "next" URL returned in the response body until no more
        pages are available.

        Args:
            path: Initial API endpoint path.
            params: Query parameters for the first request only.
            next_url_extractor: Function to extract the next URL from the response.
                                If None, looks for ``response["_links"]["next"]["href"]``
                                or ``response["next_url"]``.
            results_key: If the response is a dict, extract results from this key.
                         If None, tries ``"items"`` or ``"data"``.

        Yields:
            Lists of result items, one per page.
        """
        url: str | None = None

        while True:
            if url is None:
                response = self._get(path, params=params)
            else:
                # Resolve relative URLs against the base URL
                resolved_url = urljoin(self._base_url + "/", url)
                response = self._request("GET", resolved_url, _absolute_url=True)

            results = self._extract_results(response, results_key)
            if not results:
                break

            yield results

            # Extract next URL
            if next_url_extractor:
                url = next_url_extractor(response)
            elif isinstance(response, dict):
                links = response.get("_links", {})
                next_link = links.get("next", {})
                url = next_link.get("href") if next_link else None
                if not url:
                    url = response.get("next_url")
            else:
                url = None

            if not url:
                break

    # ------------------------------------------------------------------
    # Core request handling
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute an HTTP request with error handling and rate limiting.

        Handles 429 rate-limit responses with automatic backoff/retry.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: URL path relative to base_url.
            **kwargs: Passed to ``requests.Session.request()``.
                Special kwarg ``_raw=True`` returns the raw Response object
                instead of parsing JSON.

        Returns:
            Parsed JSON response, raw Response (if _raw=True), or None for 204.

        Raises:
            ApiUnauthorizedError: On 401/403.
            ApiNotFoundError: On 404.
            ApiRateLimitError: On 429 after max retries exhausted.
            ApiServerError: On 5xx after retries.
            ApiClientError: On other HTTP errors.
        """
        raw = kwargs.pop("_raw", False)
        absolute_url = kwargs.pop("_absolute_url", False)
        url = path if absolute_url else self._build_url(path)
        kwargs.setdefault("timeout", self._timeout)

        self._apply_rate_limit()

        attempt = 0
        while True:
            response = self._session.request(method, url, **kwargs)
            self._last_request_time = time.monotonic()

            if response.status_code == 204:
                return None

            if response.ok:
                if raw:
                    return response
                return self._parse_response(response)

            # Handle retryable errors
            if response.status_code == 429:
                attempt += 1
                if attempt > self._max_retries:
                    retry_after = self._get_retry_after(response)
                    raise ApiRateLimitError(
                        f"Rate limited on {method} {path} after {self._max_retries} retries",
                        status_code=429,
                        response_body=self._safe_response_body(response),
                        retry_after=retry_after,
                    )
                wait_time = self._compute_retry_wait(response, attempt)
                logger.warning(
                    "Rate limited (429), retrying in %.1fs (attempt %d/%d)",
                    wait_time,
                    attempt,
                    self._max_retries,
                )
                time.sleep(wait_time)
                continue

            if response.status_code >= 500:
                attempt += 1
                if attempt > self._max_retries:
                    raise ApiServerError(
                        f"Server error {response.status_code} on {method} {path} "
                        f"after {self._max_retries} retries",
                        status_code=response.status_code,
                        response_body=self._safe_response_body(response),
                    )
                wait_time = self._backoff_factor * (2 ** (attempt - 1))
                logger.warning(
                    "Server error %d, retrying in %.1fs (attempt %d/%d)",
                    response.status_code,
                    wait_time,
                    attempt,
                    self._max_retries,
                )
                time.sleep(wait_time)
                continue

            # Non-retryable errors
            self._raise_for_status(response, method, path)

    # ------------------------------------------------------------------
    # Hooks for subclasses
    # ------------------------------------------------------------------

    def _parse_response(self, response: requests.Response) -> Any:
        """Parse a successful response. Override for non-JSON APIs."""
        return response.json()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_results(response: Any, results_key: str | None) -> Any:
        """Extract results from a paginated response."""
        if results_key:
            return response[results_key]
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            for key in ("data", "results", "items"):
                if key in response:
                    return response[key]
            return []
        return [response]

    def _build_url(self, path: str) -> str:
        """Build full URL from base and path."""
        return urljoin(self._base_url + "/", path.lstrip("/"))

    def _apply_rate_limit(self) -> None:
        """Enforce minimum interval between requests."""
        if self._rate_limit_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._rate_limit_interval:
            time.sleep(self._rate_limit_interval - elapsed)

    def _compute_retry_wait(self, response: requests.Response, attempt: int) -> float:
        """Compute wait time for retry, using Retry-After header if available."""
        retry_after = self._get_retry_after(response)
        if retry_after is not None:
            return retry_after
        return float(self._backoff_factor * (2 ** (attempt - 1)))

    @staticmethod
    def _get_retry_after(response: requests.Response) -> float | None:
        """Extract Retry-After header value in seconds."""
        retry_after = response.headers.get("Retry-After")
        if retry_after is None:
            return None
        try:
            return float(retry_after)
        except (ValueError, TypeError):
            return None

    def _raise_for_status(
        self, response: requests.Response, method: str, path: str
    ) -> None:
        """Raise typed exceptions based on status code."""
        body = self._safe_response_body(response)
        status = response.status_code

        if status in (401, 403):
            raise ApiUnauthorizedError(
                f"Unauthorized ({status}) on {method} {path}",
                status_code=status,
                response_body=body,
            )
        if status == 404:
            raise ApiNotFoundError(
                f"Not found (404) on {method} {path}",
                status_code=404,
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
            return response.text[:2000] if response.text else None
