"""API client for fetching Checkfirst data from remote endpoints."""

import time
from typing import Any, Iterator

import requests

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
    headers = {"Api-Key": api_key, "Accept": "application/json"}

    current_page = start_page
    has_more = True

    session = requests.Session()

    while has_more:
        params: dict[str, str] = {"page": str(current_page)}
        if since:
            params["since"] = since
        url = f"{base_url}{endpoint}"

        last_exc: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = session.get(url, headers=headers, params=params, timeout=600)
                response.raise_for_status()

                data = response.json()

                if "data" not in data:
                    raise APIError(
                        f"Unrecognized API response format: {list(data.keys())}"
                    )

                items = data["data"]
                has_more = data.get("pagination", {}).get("has_next", False)

                if not items:
                    has_more = False
                    break

                yield from items
                current_page += 1
                break  # success — exit retry loop

            except requests.HTTPError as exc:
                last_exc = APIError(
                    f"HTTP error {exc.response.status_code} when fetching page "
                    f"{current_page}: {exc.response.reason}"
                )
                last_exc.__cause__ = exc
            except ValueError as exc:
                last_exc = APIError(
                    f"Invalid JSON response from API on page {current_page}"
                )
                last_exc.__cause__ = exc
            except requests.RequestException as exc:
                last_exc = APIError(
                    f"Network error when fetching page {current_page}: {exc}"
                )
                last_exc.__cause__ = exc
            except APIError:
                raise

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            else:
                raise last_exc  # type: ignore[misc]
