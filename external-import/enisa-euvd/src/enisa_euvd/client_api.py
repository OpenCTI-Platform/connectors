"""ENISA EUVD API client using the connectors-sdk `BaseClientApi`.

Reference: https://euvd.enisa.europa.eu/apidoc
"""

from __future__ import annotations

import itertools
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

import requests
from connectors_sdk import ApiClientError, BaseClientApi, RateLimit
from connectors_sdk.exceptions.error import DataRetrievalError
from enisa_euvd.models import EUVDInvalidItem, EUVDVulnerability
from pydantic import ValidationError

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
        self,
        updated_after: datetime | None = None,
        min_score: float | None = None,
        exploited_only: bool = False,
    ) -> Generator[list[EUVDVulnerability | EUVDInvalidItem], None, None]:
        """Paginate `GET /search`, page by page, newest `dateUpdated` first.

        Args:
            updated_after: When set, only vulnerabilities with
                `date_updated > updated_after` (strictly) are yielded. The
                API's `fromUpdatedDate` filter only has day granularity, so it
                is sent to skip older days server-side, and the exact
                comparison is done here. The comparison is strict so the
                newest item of the previous run, whose `dateUpdated` became
                the watermark, is not sent again on every run. Since
                `/search` is sorted descending on `dateUpdated`, the first
                item at or before `updated_after` ends the pagination. A naive
                (timezone-unaware) value is treated as UTC, like the API's own
                timestamps.
            min_score: When set, sent as `fromScore`: only vulnerabilities
                with a base score greater than or equal to it are returned.
            exploited_only: When true, sent as `exploited=true`: only
                vulnerabilities with a known exploitation are returned.

        Yields:
            One page (list) of items at a time: an `EUVDVulnerability` per
            valid item, an `EUVDInvalidItem` per item that failed validation
            (see `_parse_items`).

        Raises:
            DataRetrievalError: If the API is unreachable or keeps returning
                an error once retries are exhausted.
        """
        params: dict[str, Any] = {"size": PAGE_SIZE}
        if updated_after is not None:
            if updated_after.tzinfo is None:
                updated_after = updated_after.replace(tzinfo=timezone.utc)
            params["fromUpdatedDate"] = (
                updated_after.astimezone(timezone.utc).date().isoformat()
            )
        if min_score is not None:
            params["fromScore"] = min_score
        if exploited_only:
            params["exploited"] = "true"

        for page in itertools.count():
            try:
                response = self._get("/search", params={**params, "page": page})
            except (ApiClientError, requests.RequestException) as err:
                raise DataRetrievalError(
                    f"Failed to fetch EUVD vulnerabilities (page {page}): {err}"
                ) from err
            raw_items = (response or {}).get("items") or []
            if not raw_items:
                break

            items = self._parse_items(raw_items)

            if updated_after is not None:
                in_range = [i for i in items if i.date_updated > updated_after]
                if in_range:
                    yield in_range
                if len(in_range) < len(items):
                    # Reached an item at or before the watermark: every
                    # subsequent item (this page and following ones) is older.
                    break
            elif items:
                yield items

            if len(raw_items) < PAGE_SIZE:
                break

    def _parse_items(
        self, raw_items: list[dict[str, Any]]
    ) -> list[EUVDVulnerability | EUVDInvalidItem]:
        """Validate each raw item.

        An item that fails validation is returned as an `EUVDInvalidItem` when
        its `dateUpdated` can still be read, so the processor keeps the
        watermark below it. Otherwise it cannot be placed, and is logged and
        skipped.
        """
        items: list[EUVDVulnerability | EUVDInvalidItem] = []
        for raw_item in raw_items:
            try:
                items.append(EUVDVulnerability.model_validate(raw_item))
                continue
            except ValidationError as err:
                error = str(err)
            raw = raw_item if isinstance(raw_item, dict) else {}
            try:
                items.append(
                    EUVDInvalidItem.model_validate(
                        {
                            "id": raw.get("id") or "unknown",
                            "dateUpdated": raw.get("dateUpdated"),
                            "error": error,
                        }
                    )
                )
            except ValidationError:
                self._logger.warning(
                    "Failed to parse EUVD vulnerability without a valid "
                    "dateUpdated, skipping it",
                    meta={"raw_id": raw.get("id", "unknown"), "error": error},
                )
        return items
