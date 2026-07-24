"""RST Cloud Threat Library HTTP client."""

from __future__ import annotations

import time
from typing import Any, Dict, Iterator

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class ThreatLibraryClient:
    """Paginated /v1/threat-objects/<type> reader with per-request retry."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        *,
        base_url: HttpUrl,
        api_key: str,
        auth_header: str = "x-api-key",
        connect_timeout: int = 30,
        read_timeout: int = 120,
        retry: int = 2,
        ssl_verify: bool = True,
        page_size: int = 100,
        order_by: str = "modified",
        order_mode: str = "desc",
        proxy: str = "",
    ):
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.api_key = api_key
        self.auth_header = auth_header or "x-api-key"
        self.connect_timeout = int(connect_timeout)
        self.read_timeout = int(read_timeout)
        self.retry = int(retry)
        self.ssl_verify = bool(ssl_verify)
        self.page_size = int(page_size)
        self.order_by = order_by or "modified"
        self.order_mode = (order_mode or "desc").lower()
        self.proxy = (proxy or "").strip()

        self._session = requests.Session()
        self._session.headers.update(
            {
                self.auth_header: self.api_key,
                "Accept": "application/json",
                "User-Agent": "opencti-connector-rst-threat-library",
            }
        )
        if self.proxy:
            self._session.proxies = {"http": self.proxy, "https": self.proxy}

    def iter_new_items(self, obj_type: str, cursor: str) -> Iterator[Dict[str, Any]]:
        for item in self._iter_pages(obj_type, log_label="fetched page"):
            modified = item.get("modified") or ""
            if self.order_mode == "desc" and cursor and modified and modified <= cursor:
                self.helper.connector_logger.info(
                    f"[{obj_type}] cursor reached at modified={modified}; stopping"
                )
                return
            if self.order_mode == "asc" and cursor and modified and modified <= cursor:
                continue
            yield item

    def iter_all_items(self, obj_type: str) -> Iterator[Dict[str, Any]]:
        yield from self._iter_pages(obj_type, log_label="catalogue scan")

    def _iter_pages(self, obj_type: str, *, log_label: str) -> Iterator[Dict[str, Any]]:
        url = f"{self.base_url}/threat-objects/{obj_type}"
        offset = 0
        while True:
            params = {
                "limit": self.page_size,
                "offset": offset,
                "orderBy": self.order_by,
                "orderMode": self.order_mode,
            }
            data = self._get_json(url, params)
            items = (data or {}).get("data") or []
            total = (data or {}).get("total")
            self.helper.connector_logger.info(
                f"[{obj_type}] {log_label} offset={offset} size={len(items)}"
                + (f" (total upstream={total})" if total is not None else "")
            )
            if not items:
                return
            yield from items
            if len(items) < self.page_size:
                return
            offset += self.page_size

    def _get_json(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        last_exc = None
        for attempt in range(self.retry + 1):
            try:
                response = self._session.get(
                    url,
                    params=params,
                    timeout=(self.connect_timeout, self.read_timeout),
                    verify=self.ssl_verify,
                )
                if response.status_code == 429 or 500 <= response.status_code < 600:
                    raise requests.HTTPError(
                        f"{response.status_code} {response.reason} for {response.url}",
                        response=response,
                    )
                response.raise_for_status()
                return response.json()
            except Exception as exc:
                last_exc = exc
                if isinstance(exc, requests.HTTPError):
                    status = getattr(
                        getattr(exc, "response", None), "status_code", None
                    )
                    if status is not None and 400 <= status < 500 and status != 429:
                        raise
                if attempt < self.retry:
                    delay = (attempt + 1) * 2
                    self.helper.connector_logger.warning(
                        "GET request failed; retrying",
                        {
                            "url": url,
                            "attempt": attempt + 1,
                            "max_attempts": self.retry + 1,
                            "error": str(exc),
                            "retry_in_seconds": delay,
                        },
                    )
                    time.sleep(delay)
                else:
                    raise
        raise last_exc  # type: ignore[misc]
