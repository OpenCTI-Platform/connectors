"""
USTA API client.

Handles communication with all six USTA Threat Stream v4 endpoints:
  - .../security-intelligence/ioc/malicious-urls                                          (cursor-based pagination)
  - .../security-intelligence/ioc/phishing-sites                                          (page-based pagination)
  - .../security-intelligence/ioc/malware-hashes                                          (cursor-based pagination)
  - .../security-intelligence/account-takeover-prevention/compromised-credentials-tickets (page-based, order param)
  - .../fraud-intelligence/credit-card-tickets                                            (page-based, ordering param)
  - .../deep-sight-tickets                                                                (page-based pagination)

Implements rate limiting (via limiter) and retry logic (via tenacity)
as prescribed by the OpenCTI connector specification.
"""

from __future__ import annotations

from typing import Any, Generator
from urllib.parse import urljoin

import requests
from limiter import Limiter
from pycti import OpenCTIConnectorHelper
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)


def _is_retryable_error(exc: BaseException) -> bool:
    """Return True only for transient errors worth retrying (timeouts, 429, 5xx)."""
    if isinstance(
        exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)
    ):
        return True
    if isinstance(exc, requests.exceptions.HTTPError):
        response = exc.response
        return response is not None and (
            response.status_code == 429 or response.status_code >= 500
        )
    return False


class UstaClientError(Exception):
    """Raised when the USTA API returns an unexpected error."""


class UstaClient:
    """
    Client for the USTA Threat Stream v4 Security Intelligence API.

    Supports automatic pagination across all six IOC / ticket endpoint families.
    """

    API_PREFIX = "/api/threat-stream/v4"
    API_PREFIX_IOC = f"{API_PREFIX}/security-intelligence/ioc"
    API_PREFIX_ATP = f"{API_PREFIX}/security-intelligence/account-takeover-prevention"
    API_PREFIX_FRAUD = f"{API_PREFIX}/fraud-intelligence"

    ENDPOINT_MALICIOUS_URLS = f"{API_PREFIX_IOC}/malicious-urls"
    ENDPOINT_PHISHING_SITES = f"{API_PREFIX_IOC}/phishing-sites"
    ENDPOINT_MALWARE_HASHES = f"{API_PREFIX_IOC}/malware-hashes"
    ENDPOINT_COMPROMISED_CREDENTIALS = (
        f"{API_PREFIX_ATP}/compromised-credentials-tickets"
    )
    ENDPOINT_CREDIT_CARDS = f"{API_PREFIX_FRAUD}/credit-card-tickets"
    ENDPOINT_DEEP_SIGHT_TICKETS = f"{API_PREFIX}/deep-sight-tickets"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        api_key: str,
        page_size: int = 100,
    ) -> None:
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.api_key = api_key
        self.page_size = page_size

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "USTA-OpenCTI-Integration/1.0",
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
            }
        )

        # Rate limiter: 10 requests per second, bucket capacity of 20
        self.rate_limiter = Limiter(
            rate=10,
            capacity=20,
            bucket=b"usta",
        )

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(initial=2, max=120, jitter=2),
        retry=retry_if_exception(_is_retryable_error),
    )
    def _request(self, url: str, params: dict[str, Any] | None = None) -> dict:
        """
        Execute a single HTTP GET request with retry and rate limiting.

        Args:
            url: Full URL or path relative to base_url.
            params: Optional query parameters.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            UstaClientError: On all permanent errors (401, 403, and non-retryable 4xx).
            requests.exceptions.HTTPError: On transient errors (429, 5xx) — consumed
                internally by the tenacity retry decorator.
        """
        # Build absolute URL if a relative path was given
        if url.startswith("http://") or url.startswith("https://"):
            full_url = url
        else:
            full_url = urljoin(self.base_url, url)

        with self.rate_limiter:
            self.helper.connector_logger.debug(
                "[USTA_CLIENT] Requesting",
                {"url": full_url, "params": params},
            )
            response = self.session.get(full_url, params=params, timeout=60)

        if response.status_code == 401:
            raise UstaClientError(
                f"Authentication failed (HTTP 401) for {full_url}. "
                "Verify your USTA_API_KEY."
            )
        if response.status_code == 403:
            raise UstaClientError(
                f"Access denied (HTTP 403) for {full_url}. "
                "Your API key may lack the required permissions for this endpoint."
            )

        if not response.ok:
            self.helper.connector_logger.warning(
                "[USTA_CLIENT] Unexpected HTTP error response",
                {
                    "url": full_url,
                    "http_status": response.status_code,
                    "response_preview": response.text[:500],
                },
            )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            if _is_retryable_error(exc):
                raise  # Let the tenacity retry decorator handle transient errors
            raise UstaClientError(
                f"Permanent HTTP error {response.status_code} for {full_url}: "
                f"{response.text[:200]}"
            ) from exc
        try:
            return response.json()
        except ValueError as exc:
            self.helper.connector_logger.warning(
                "[USTA_CLIENT] Failed to decode JSON response",
                {
                    "url": full_url,
                    "http_status": response.status_code,
                    "content_type": response.headers.get("Content-Type"),
                    "response_preview": response.text[:500],
                },
            )
            raise UstaClientError(
                f"Non-JSON response from {full_url} (status {response.status_code})"
            ) from exc

    # ------------------------------------------------------------------
    # Cursor-based pagination (malicious-urls and malware-hashes)
    # ------------------------------------------------------------------

    def _fetch_cursor_paginated(
        self,
        endpoint: str,
        start: str,
        ordering: str = "created",
    ) -> Generator[list[dict], None, None]:
        """
        Generator that yields pages (list of result dicts) from a
        cursor-paginated USTA endpoint.

        The API returns:
            {
                "cursor": "<opaque>",
                "next": "<full url for next page or null>",
                "results": [...]
            }

        Args:
            endpoint: Relative API path (e.g. /api/.../malicious-urls).
            start: ISO-8601 datetime string for the start filter.
            ordering: Field to order by (always 'created').

        Yields:
            Lists of result dictionaries per page.
        """
        params: dict[str, Any] = {
            "ordering": ordering,
            "start": start,
            "size": self.page_size,
            "format": "json",
        }

        url = endpoint
        page_num = 0

        while True:
            data = self._request(url, params=params)

            page_num += 1
            results = data.get("results", [])
            self.helper.connector_logger.info(
                "[USTA_CLIENT] Cursor-paginated page received",
                {
                    "endpoint": endpoint,
                    "page": page_num,
                    "results_in_page": len(results),
                    "has_next": bool(data.get("next")),
                },
            )

            if results:
                yield results

            next_url = data.get("next")
            if not next_url or not results:
                self.helper.connector_logger.debug(
                    "[USTA_CLIENT] Cursor pagination exhausted",
                    {"endpoint": endpoint, "total_pages": page_num},
                )
                break

            url = next_url
            if params:
                params = {}

    # ------------------------------------------------------------------
    # Page-based pagination (phishing-sites)
    # ------------------------------------------------------------------

    def _fetch_page_paginated(
        self,
        endpoint: str,
        start: str | None = None,
        ordering: str = "created",
        order_param_name: str = "ordering",
    ) -> Generator[list[dict], None, None]:
        """
        Generator that yields pages from a standard page-number-paginated
        USTA endpoint.

        The API returns:
            {
                "count": N,
                "next": "<full url for next page or null>",
                "previous": "<full url or null>",
                "results": [...]
            }

        Args:
            endpoint: Relative API path.
            start: ISO-8601 datetime string.
            ordering: Value for the ordering field (e.g. 'created').
            order_param_name: Query parameter key name. Most endpoints use
                'ordering', but compromised-credentials uses 'order'.

        Yields:
            Lists of result dictionaries per page.
        """
        params: dict[str, Any] = {
            order_param_name: ordering,
            "size": self.page_size,
            "format": "json",
        }
        if start:
            params["start"] = start

        url = endpoint
        page_num = 0

        while True:
            data = self._request(url, params=params)

            page_num += 1
            total_count = data.get("count")
            results = data.get("results", [])
            self.helper.connector_logger.debug(
                "[USTA_CLIENT] Page-paginated page received",
                {
                    "endpoint": endpoint,
                    "page": page_num,
                    "results_in_page": len(results),
                    "total_count": total_count,
                    "has_next": bool(data.get("next")),
                },
            )
            if results:
                yield results

            next_url = data.get("next")
            if not next_url or not results:
                self.helper.connector_logger.debug(
                    "[USTA_CLIENT] Page pagination exhausted",
                    {
                        "endpoint": endpoint,
                        "total_pages": page_num,
                        "total_count": total_count,
                    },
                )
                break

            url = next_url
            if params:
                params = {}

    # ------------------------------------------------------------------
    # Public high-level methods
    # ------------------------------------------------------------------

    def get_malicious_urls(self, start: str) -> Generator[list[dict], None, None]:
        """
        Fetch malicious URL IOCs created since `start`.

        Args:
            start: ISO-8601 datetime string (e.g. '2026-01-01T00:00:00Z').

        Yields:
            Pages of malicious URL result dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching malicious URLs",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_cursor_paginated(
            self.ENDPOINT_MALICIOUS_URLS, start=start
        )

    def get_phishing_sites(self, start: str) -> Generator[list[dict], None, None]:
        """
        Fetch phishing site IOCs created since `start`.

        Args:
            start: ISO-8601 datetime string.

        Yields:
            Pages of phishing site result dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching phishing sites",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_page_paginated(self.ENDPOINT_PHISHING_SITES, start=start)

    def get_malware_hashes(self, start: str) -> Generator[list[dict], None, None]:
        """
        Fetch malware hash IOCs created since `start`.

        Args:
            start: ISO-8601 datetime string.

        Yields:
            Pages of malware hash result dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching malware hashes",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_cursor_paginated(
            self.ENDPOINT_MALWARE_HASHES, start=start
        )

    def get_compromised_credentials(
        self, start: str
    ) -> Generator[list[dict], None, None]:
        """
        Fetch compromised credentials tickets created since `start`.

        NOTE: This endpoint uses the query parameter ``order`` (not
        ``ordering``) based on the observed API contract.

        Args:
            start: ISO-8601 datetime string.

        Yields:
            Pages of compromised credentials ticket dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching compromised credentials tickets",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_page_paginated(
            self.ENDPOINT_COMPROMISED_CREDENTIALS,
            start=start,
            order_param_name="order",
        )

    def get_credit_card_tickets(self, start: str) -> Generator[list[dict], None, None]:
        """
        Fetch credit card fraud tickets created since `start`.

        Args:
            start: ISO-8601 datetime string.

        Yields:
            Pages of credit card ticket dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching credit card fraud tickets",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_page_paginated(self.ENDPOINT_CREDIT_CARDS, start=start)

    def get_deep_sight_tickets(self, start: str) -> Generator[list[dict], None, None]:
        """
        Fetch Deep Sight intelligence tickets created since `start`.

        Args:
            start: ISO-8601 datetime string.

        Yields:
            Pages of Deep Sight ticket dicts.
        """
        self.helper.connector_logger.info(
            "[USTA_CLIENT] Fetching Deep Sight tickets",
            {"start": start, "page_size": self.page_size},
        )
        yield from self._fetch_page_paginated(
            self.ENDPOINT_DEEP_SIGHT_TICKETS, start=start
        )
