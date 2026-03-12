"""
USTA Prodaft API client.

Handles communication with all five USTA Threat Stream v4 endpoints:
  - /ioc/malicious-urls                    (cursor-based pagination)
  - /ioc/phishing-sites                    (page-based pagination)
  - /ioc/malware-hashes                    (cursor-based pagination)
  - /account-takeover-prevention/compromised-credentials-tickets  (page-based, order param)
  - /fraud-intelligence/credit-card-tickets                       (page-based, ordering param)

Implements rate limiting (via limiter) and retry logic (via tenacity)
as prescribed by the OpenCTI connector specification.
"""

from __future__ import annotations

from typing import Any, Generator

import requests
from limiter import Limiter
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)


class UstaClientError(Exception):
    """Raised when the USTA API returns an unexpected error."""


class UstaClient:
    """
    Client for the USTA Prodaft Threat Stream v4 Security Intelligence API.

    Supports automatic pagination across all five IOC / ticket endpoint families.
    """

    API_PREFIX_IOC = "/api/threat-stream/v4/security-intelligence/ioc"
    API_PREFIX_ATP = "/api/threat-stream/v4/security-intelligence/account-takeover-prevention"
    API_PREFIX_FRAUD = "/api/threat-stream/v4/fraud-intelligence"

    ENDPOINT_MALICIOUS_URLS = f"{API_PREFIX_IOC}/malicious-urls"
    ENDPOINT_PHISHING_SITES = f"{API_PREFIX_IOC}/phishing-sites"
    ENDPOINT_MALWARE_HASHES = f"{API_PREFIX_IOC}/malware-hashes"
    ENDPOINT_COMPROMISED_CREDENTIALS = f"{API_PREFIX_ATP}/compromised-credentials-tickets"
    ENDPOINT_CREDIT_CARDS = f"{API_PREFIX_FRAUD}/credit-card-tickets"

    def __init__(
        self,
        helper,
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
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
            }
        )

        # Rate limiter: 10 requests per second, bucket capacity of 20
        self.rate_limiter = Limiter(
            rate=10,
            capacity=20,
            bucket="usta_prodaft",
        )

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(initial=2, max=120, jitter=2),
        retry=retry_if_exception_type(
            (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.HTTPError,
            )
        ),
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
            UstaClientError: On non-retryable API errors.
            requests.exceptions.HTTPError: On retryable HTTP errors (triggers retry).
        """
        # Build absolute URL if a relative path was given
        if url.startswith("http://") or url.startswith("https://"):
            full_url = url
        else:
            full_url = f"{self.base_url}{url}"

        with self.rate_limiter:
            self.helper.connector_logger.debug(
                "[USTA_CLIENT] Requesting",
                {"url": full_url, "params": params},
            )
            response = self.session.get(full_url, params=params, timeout=60)

        if response.status_code == 401:
            raise UstaClientError(
                "Authentication failed. Verify your USTA_PRODAFT_API_KEY."
            )
        if response.status_code == 403:
            raise UstaClientError(
                "Access denied. Your API key may lack required permissions."
            )

        response.raise_for_status()
        return response.json()

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
        is_first_request = True

        while True:
            if is_first_request:
                data = self._request(url, params=params)
                is_first_request = False
            else:
                # Subsequent requests use the full "next" URL provided by API
                data = self._request(url)

            results = data.get("results", [])
            if results:
                yield results

            next_url = data.get("next")
            if not next_url or not results:
                break

            url = next_url

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
        is_first_request = True

        while True:
            if is_first_request:
                data = self._request(url, params=params)
                is_first_request = False
            else:
                data = self._request(url)

            results = data.get("results", [])
            if results:
                yield results

            next_url = data.get("next")
            if not next_url or not results:
                break

            url = next_url

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
        yield from self._fetch_page_paginated(
            self.ENDPOINT_PHISHING_SITES, start=start
        )

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

    def get_credit_card_tickets(
        self, start: str
    ) -> Generator[list[dict], None, None]:
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
        yield from self._fetch_page_paginated(
            self.ENDPOINT_CREDIT_CARDS, start=start
        )
