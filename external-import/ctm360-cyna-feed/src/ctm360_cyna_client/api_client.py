import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests
from pycti import OpenCTIConnectorHelper


class CTM360CynaAPIError(Exception):
    """Custom exception for CTM360 CYNA API errors."""

    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message)


class CTM360CynaClient:
    """HTTP client for the CTM360 CYNA (Cyber News & Alerts) API.

    Handles authentication, retry with linear backoff, rate limiting,
    and cursor-based pagination.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
    ):
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"api-key": api_key})
        self.session.verify = True
        self._max_retries = 3
        self._retry_delay = 5
        # Upper bound (seconds) for any server-provided Retry-After, so a
        # misbehaving server (e.g. a far-future HTTP-date or an absurdly large
        # delay-seconds value) cannot pin the connector sleeping for an
        # unbounded amount of time.
        self._max_retry_after = 300

    def _parse_retry_after(self, header_value, fallback: int) -> int:
        """Parse a ``Retry-After`` header into a non-negative delay in seconds.

        ``Retry-After`` may be either an integer number of seconds or an
        HTTP-date (RFC 7231). The resulting delay is clamped to
        ``[0, self._max_retry_after]`` so a misbehaving server cannot pin the
        connector sleeping for an unbounded amount of time, while smaller
        server-provided delays are still honoured. Any missing or malformed
        value falls back to the configured linear backoff so a non-integer
        header can never bypass the retry handling with an unexpected
        ``ValueError``.
        """
        if header_value is None:
            return fallback

        # Integer "delay-seconds" form.
        try:
            return self._clamp_retry_after(int(header_value))
        except (TypeError, ValueError):
            pass

        # HTTP-date form.
        try:
            retry_dt = parsedate_to_datetime(header_value)
        except (TypeError, ValueError):
            return fallback
        if retry_dt is None:
            return fallback
        if retry_dt.tzinfo is None:
            retry_dt = retry_dt.replace(tzinfo=timezone.utc)
        delta = (retry_dt - datetime.now(timezone.utc)).total_seconds()
        return self._clamp_retry_after(int(delta))

    def _clamp_retry_after(self, seconds: int) -> int:
        """Clamp a Retry-After delay to ``[0, self._max_retry_after]``."""
        return max(0, min(seconds, self._max_retry_after))

    def _request(
        self,
        method: str,
        path: str,
        params: dict = None,
    ) -> dict:
        """Execute an HTTP request with retry and rate-limit handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (e.g., '/api/v1/news')
            params: Query parameters dict.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CTM360CynaAPIError: On unrecoverable API errors.
        """
        url = f"{self.base_url}{path}"

        for attempt in range(self._max_retries):
            try:
                self.helper.connector_logger.debug(
                    "[API] Request",
                    meta={
                        "method": method,
                        "url": url,
                        "params": params,
                        "attempt": attempt + 1,
                    },
                )
                response = self.session.request(method, url, params=params, timeout=60)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = self._parse_retry_after(
                        response.headers.get("Retry-After"),
                        self._retry_delay * (attempt + 1),
                    )
                    self.helper.connector_logger.warning(
                        "[API] Rate limited, waiting",
                        meta={"retry_after": retry_after},
                    )
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                # Retry the whole 5xx range (e.g. 500/502/503/504) — these are
                # transient server-side failures.
                if status >= 500 and attempt < self._max_retries - 1:
                    wait_time = self._retry_delay * (attempt + 1)
                    self.helper.connector_logger.warning(
                        "[API] Server error, retrying",
                        meta={"status": status, "wait": wait_time},
                    )
                    time.sleep(wait_time)
                    continue
                raise CTM360CynaAPIError(
                    f"HTTP {status}: {str(e)}", status_code=status
                ) from e

            except requests.exceptions.ConnectionError as e:
                if attempt < self._max_retries - 1:
                    wait_time = self._retry_delay * (attempt + 1)
                    self.helper.connector_logger.warning(
                        "[API] Connection error, retrying",
                        meta={"error": str(e), "wait": wait_time},
                    )
                    time.sleep(wait_time)
                    continue
                raise CTM360CynaAPIError(f"Connection error: {str(e)}") from e

            except requests.exceptions.Timeout as e:
                if attempt < self._max_retries - 1:
                    wait_time = self._retry_delay * (attempt + 1)
                    self.helper.connector_logger.warning(
                        "[API] Timeout, retrying",
                        meta={"error": str(e), "wait": wait_time},
                    )
                    time.sleep(wait_time)
                    continue
                raise CTM360CynaAPIError(f"Request timeout: {str(e)}") from e

        raise CTM360CynaAPIError("Max retries exceeded")

    def ping(self):
        """Validate API connectivity by fetching a single news item.

        Raises:
            CTM360CynaAPIError: If the API is unreachable or auth fails.
        """
        response = self._request("GET", "/api/v1/news", params={"size": 1})
        if not response.get("success", False):
            raise CTM360CynaAPIError(
                f"API ping failed: {response.get('message', 'unknown error')}",
                status_code=response.get("statusCode"),
            )
        self.helper.connector_logger.debug(
            "[API] Ping successful",
            meta={"total": response.get("total", {}).get("value", 0)},
        )

    def get_news_page(
        self,
        size: int = 25,
        search_after: str = None,
    ) -> dict:
        """Fetch a single page of news items.

        Args:
            size: Number of items per page.
            search_after: Cursor token for pagination (from previous response).

        Returns:
            Full API response dict with 'data', 'hasMore', 'nextSearchAfter'.
        """
        params = {"size": size}
        if search_after:
            params["searchAfter"] = search_after

        response = self._request("GET", "/api/v1/news", params=params)

        if not response.get("success", False):
            raise CTM360CynaAPIError(
                f"API error: {response.get('message', 'unknown error')}",
                status_code=response.get("statusCode"),
            )

        return response

    def get_all_news(
        self,
        page_size: int = 25,
        max_pages: int = 100,
    ) -> list[dict]:
        """Fetch all news items using cursor-based pagination.

        Iterates through pages until hasMore is False or max_pages is reached.

        Args:
            page_size: Number of items per page.
            max_pages: Maximum pages to fetch (safety limit).

        Returns:
            Flat list of all news item dicts across all pages.
        """
        all_items = []
        cursor = None
        page_count = 0

        while page_count < max_pages:
            page_count += 1
            self.helper.connector_logger.info(
                "[API] Fetching page",
                meta={"page": page_count, "cursor": cursor is not None},
            )

            response = self.get_news_page(size=page_size, search_after=cursor)
            data = response.get("data", [])

            if data:
                all_items.extend(data)

            self.helper.connector_logger.debug(
                "[API] Page fetched",
                meta={
                    "page": page_count,
                    "items_on_page": len(data),
                    "total_collected": len(all_items),
                    "has_more": response.get("hasMore", False),
                },
            )

            # Check if there are more pages
            has_more = response.get("hasMore", False)
            next_cursor = response.get("nextSearchAfter")

            if not has_more or not next_cursor:
                break

            cursor = next_cursor

        self.helper.connector_logger.info(
            "[API] Pagination complete",
            meta={"total_pages": page_count, "total_items": len(all_items)},
        )

        return all_items
