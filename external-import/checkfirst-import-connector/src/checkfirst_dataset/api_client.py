"""API client for fetching Checkfirst data from remote endpoints.

This module handles paginated API requests to fetch Checkfirst data
from a remote API server.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from typing import Any, Iterator

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 5


class APIError(Exception):
    """Raised when API requests fail."""

    pass


def fetch_paginated_data(
    *,
    api_url: str,
    api_key: str,
    api_endpoint: str,
    start_page: int = 1,
    since: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Fetch paginated data from the API endpoint.

    Args:
        api_url: Base URL of the API (e.g., "https://api.example.com")
        api_key: API key for authentication
        api_endpoint: Endpoint path (e.g., "/v1/articles")
        start_page: Starting page number for pagination (default: 1)
        since: Only fetch articles published on or after this ISO 8601 date

    Yields:
        Dictionary objects representing each row/article from the API

    Raises:
        APIError: If the API request fails or returns invalid data
    """
    base_url = api_url.rstrip("/")
    endpoint = api_endpoint if api_endpoint.startswith("/") else f"/{api_endpoint}"

    current_page = start_page
    has_more = True

    while has_more:
        # Construct URL with pagination and optional since filter
        params = {"page": str(current_page)}
        if since:
            params["since"] = since
        url = f"{base_url}{endpoint}?{urllib.parse.urlencode(params)}"

        # Retry loop for transient failures
        last_exc: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            # Create request with headers (fresh request object per attempt)
            req = urllib.request.Request(url)
            req.add_header("Api-Key", api_key)
            req.add_header("Accept", "application/json")

            try:
                with urllib.request.urlopen(req, timeout=600) as response:
                    if response.status != 200:
                        raise APIError(
                            f"API request failed with status {response.status}: {response.reason}"
                        )

                    data = json.loads(response.read().decode("utf-8"))

                    # Handle different pagination response formats
                    if "data" in data:
                        items = data["data"]
                        pagination = data.get("pagination", {})
                        has_more = pagination.get("has_next", False)
                    else:
                        raise APIError(
                            f"Unrecognized API response format: {list(data.keys())}"
                        )

                    if not items:
                        has_more = False
                        break

                    for item in items:
                        yield item

                    current_page += 1
                    break  # Success — exit retry loop

            except urllib.error.HTTPError as exc:
                error_body = (
                    exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                )
                last_exc = APIError(
                    f"HTTP error {exc.code} when fetching page {current_page}: {exc.reason}. "
                    f"Response: {error_body}"
                )
                last_exc.__cause__ = exc
            except urllib.error.URLError as exc:
                last_exc = APIError(
                    f"Network error when fetching page {current_page}: {exc.reason}"
                )
                last_exc.__cause__ = exc
            except json.JSONDecodeError as exc:
                last_exc = APIError(
                    f"Invalid JSON response from API on page {current_page}"
                )
                last_exc.__cause__ = exc
            except APIError:
                raise
            except Exception as exc:
                last_exc = APIError(
                    f"Unexpected error fetching page {current_page}: {exc}"
                )
                last_exc.__cause__ = exc

            # If we get here, the attempt failed — retry or give up
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_SECONDS * attempt
                time.sleep(wait)
            else:
                raise last_exc  # type: ignore[misc]
