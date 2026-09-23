"""ENISA EUVD API client using the connectors-sdk `BaseClientApi`.

Reference: https://euvd.enisa.europa.eu/apidoc
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from connectors_sdk import BaseClientApi, RateLimit
from enisa_euvd.models import EUVDVulnerability

PAGE_SIZE = 100
# EUVD publishes no documented rate limit; stay defensive and proactively
# throttle rather than rely solely on reactive retries.
RATE_LIMIT = 2  # requests per second
MAX_RETRIES = 5
BACKOFF_FACTOR = 2.0
TIMEOUT = 60
USER_AGENT = (
    "OpenCTI-ENISA-EUVD-Connector/1.0 (+https://github.com/OpenCTI-Platform/connectors)"
)


class EnisaEuvdClient(BaseClientApi):
    """HTTP client for the public, key-less ENISA EUVD API."""

    def __init__(self, base_url: str, logger: Any, **kwargs: Any) -> None:
        kwargs.setdefault("timeout", TIMEOUT)
        kwargs.setdefault("max_retries", MAX_RETRIES)
        kwargs.setdefault("backoff_factor", BACKOFF_FACTOR)
        kwargs.setdefault("rate_limit", RateLimit(RATE_LIMIT, "second"))
        kwargs.setdefault("raise_on_limit_exceeded", False)
        super().__init__(base_url, **kwargs)
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        return {"User-Agent": USER_AGENT}

    def iter_vulnerabilities(
        self, cutoff: datetime | None = None
    ) -> Generator[list[EUVDVulnerability], None, None]:
        """Paginate `GET /search`, page by page, newest `dateUpdated` first.

        Args:
            cutoff: When set, only vulnerabilities with `date_updated >= cutoff`
                are yielded. Since `/search`'s default order is descending on
                `dateUpdated` (verified against the live API), the first item
                older than `cutoff` means every following item -- on this page
                and on any subsequent page -- is older too, so pagination stops
                immediately instead of fetching pages that would be entirely
                discarded. A naive (timezone-unaware) `cutoff` is treated as
                UTC, matching the API's own (always UTC) timestamps.

        Yields:
            One page (list) of validated `EUVDVulnerability` at a time. Items
            that fail validation are logged and skipped, never raised.
        """
        if cutoff is not None and cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)

        page = 0
        while True:
            response = self._get("/search", params={"page": page, "size": PAGE_SIZE})
            raw_items = (response or {}).get("items") or []
            if not raw_items:
                break

            vulnerabilities = self._parse_items(raw_items)

            if cutoff is not None:
                in_range = [v for v in vulnerabilities if v.date_updated >= cutoff]
                if in_range:
                    yield in_range
                if len(in_range) < len(vulnerabilities):
                    # Reached an item older than the cutoff: every subsequent
                    # item (this page and following ones) is older still.
                    break
            elif vulnerabilities:
                yield vulnerabilities

            if len(raw_items) < PAGE_SIZE:
                break
            page += 1

    def _parse_items(self, raw_items: list[dict[str, Any]]) -> list[EUVDVulnerability]:
        """Validate each raw item, logging and skipping malformed ones."""
        vulnerabilities = []
        for raw_item in raw_items:
            raw_id = (
                raw_item.get("id", "unknown")
                if isinstance(raw_item, dict)
                else "unknown"
            )
            try:
                vulnerabilities.append(EUVDVulnerability.model_validate(raw_item))
            except Exception as e:
                self._logger.warning(
                    "Failed to parse EUVD vulnerability, skipping it",
                    {"raw_id": raw_id, "error": str(e)},
                )
        return vulnerabilities
