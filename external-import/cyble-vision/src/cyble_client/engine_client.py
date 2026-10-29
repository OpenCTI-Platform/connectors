"""HTTP client for Cyble engine document APIs (advisory, newsfeed, newsflash)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generator

from connectors_sdk import ApiClientError, BaseClientApi
from cyble_client.engine_dates import iso_date, next_page

ADVISORY_PATH = "/engine/api/v1/y/advisory"
NEWSFEED_PATH = "/engine/api/v1/y/news/feed"
NEWSFLASH_PATH = "/engine/api/v1/y/flash/report"
MAX_PAGES = 1000


class CybleEngineClient(BaseClientApi):
    """Paginated GETs for Cyble research documents."""

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        page_size: int,
        logger,
    ) -> None:
        super().__init__(base_url=base_url.rstrip("/"))
        self._api_token = api_token
        self._page_size = page_size
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_token}",
        }

    def iter_advisories(
        self, *, since: datetime, until: datetime
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield advisory catalog cards in publish_date order."""
        params = {
            "dateRange": f"{iso_date(since)},{iso_date(until)}",
            "sortBy": "publish_date",
            "order": "asc",
            "limit": self._page_size,
        }
        yield from self._iter_pages(
            path=ADVISORY_PATH,
            params=params,
            rows_key="reports",
            total_from=lambda payload: payload.get("pagination") or {},
            product="advisory",
        )

    def iter_newsfeed(
        self, *, since: datetime, until: datetime
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield newsfeed articles in post_date order."""
        params = {
            "start_date": iso_date(since),
            "end_date": iso_date(until),
            "order_by": "post_date",
            "order_dir": "asc",
            "limit": self._page_size,
        }
        yield from self._iter_pages(
            path=NEWSFEED_PATH,
            params=params,
            rows_key="results",
            total_from=lambda payload: payload,
            product="newsfeed",
        )

    def iter_newsflash(
        self, *, since: datetime, until: datetime
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield newsflash spot reports in published_date order."""
        params = {
            "startDate": iso_date(since),
            "endDate": iso_date(until),
            "orderBy": "published_date",
            "orderDir": "asc",
            "limit": self._page_size,
        }
        yield from self._iter_pages(
            path=NEWSFLASH_PATH,
            params=params,
            rows_key="results",
            total_from=lambda payload: payload,
            product="newsflash",
        )

    def _iter_pages(
        self,
        *,
        path: str,
        params: dict[str, Any],
        rows_key: str,
        total_from,
        product: str,
    ) -> Generator[list[dict[str, Any]], None, None]:
        page = 1
        for _ in range(MAX_PAGES):
            query = {**params, "page": page}
            response = self._get(path, params=query)
            payload = self._payload(response, path)
            rows = payload.get(rows_key) or []
            if not isinstance(rows, list):
                rows = []

            meta = total_from(payload) or {}
            total = _as_int(
                meta.get("total", meta.get("total_count")), default=len(rows)
            )
            per_page = (
                _as_int(meta.get("items_per_page"), default=self._page_size)
                or self._page_size
            )

            self._logger.info(
                "Fetched Cyble engine page",
                {
                    "product": product,
                    "page": page,
                    "count": len(rows),
                    "total": total,
                },
            )
            if rows:
                yield rows

            nxt = next_page(page, per_page, total)
            if nxt is None or not rows:
                return
            page = nxt

        self._logger.warning(
            "Stopped Cyble engine pagination at page cap",
            {"product": product, "max_pages": MAX_PAGES},
        )

    @staticmethod
    def _payload(response: Any, path: str) -> dict[str, Any]:
        if not isinstance(response, dict):
            raise ApiClientError(f"Unexpected engine response on GET {path}")
        if response.get("success") is False:
            raise ApiClientError(f"Engine API returned success=false on GET {path}")
        data = response.get("data")
        return data if isinstance(data, dict) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
