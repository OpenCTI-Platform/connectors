"""Splunk REST client."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import requests


class SplunkClientError(RuntimeError):
    """Raised when Splunk returns an error or an unexpected response."""


class SplunkClient:
    """Small wrapper around Splunk management and search REST endpoints."""

    _RETRY_STATUS_CODES = {429, 503}

    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool = True,
        timeout_seconds: int = 60,
        owner: str = "-",
        app: str = "-",
        es_api_prefix: str = "/servicesNS/nobody/missioncontrol/public/v2",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout_seconds = timeout_seconds
        self.owner = owner
        self.app = app
        self.es_api_prefix = es_api_prefix.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )

    def get_saved_searches(
        self, include_disabled: bool = False, count: int = 500
    ) -> list[dict[str, Any]]:
        path = (
            f"/servicesNS/{quote(self.owner)}/{quote(self.app)}/saved/searches"
        )
        params = {"output_mode": "json", "count": count, "offset": 0}
        searches = self._get_paginated(path=path, params=params, count=count)
        if include_disabled:
            return searches
        return [
            search
            for search in searches
            if not self._to_bool(search.get("content", {}).get("disabled"))
        ]

    def get_assets_identities(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for endpoint, record_type in (
            ("assets", "asset"),
            ("identities", "identity"),
        ):
            for row in self._get_json_list(f"{self.es_api_prefix}/{endpoint}"):
                row.setdefault("record_type", record_type)
                records.append(row)
        return records

    def get_findings(self, earliest_time: str | None = None) -> list[dict[str, Any]]:
        params = {"earliest_time": earliest_time} if earliest_time else None
        return self._get_json_list(f"{self.es_api_prefix}/findings", params=params)

    def run_search(
        self,
        search: str,
        earliest_time: str | None = None,
        latest_time: str | None = None,
        max_records: int = 10000,
    ) -> list[dict[str, Any]]:
        data = {
            "search": search if search.startswith("search ") else f"search {search}",
            "output_mode": "json",
            "exec_mode": "normal",
        }
        if earliest_time:
            data["earliest_time"] = earliest_time
        if latest_time:
            data["latest_time"] = latest_time

        response = self._request("POST", "/services/search/jobs", data=data)
        sid = response.get("sid")
        if not sid:
            raise SplunkClientError("Splunk did not return a search sid")

        self._wait_for_search(str(sid))
        return self._get_search_results(str(sid), max_records=max_records)

    def _wait_for_search(self, sid: str) -> None:
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            response = self._request(
                "GET",
                f"/services/search/jobs/{quote(sid)}",
                params={"output_mode": "json"},
            )
            content = self._first_entry_content(response)
            if self._to_bool(content.get("isDone")):
                return
            time.sleep(1)
        raise SplunkClientError(f"Splunk search '{sid}' did not complete before timeout")

    def _get_search_results(self, sid: str, max_records: int) -> list[dict[str, Any]]:
        count = 500
        offset = 0
        results: list[dict[str, Any]] = []
        while True:
            response = self._request(
                "GET",
                f"/services/search/jobs/{quote(sid)}/results",
                params={
                    "output_mode": "json",
                    "count": count,
                    "offset": offset,
                },
            )
            page = response.get("results", [])
            if not isinstance(page, list):
                raise SplunkClientError("Splunk search results response is malformed")
            results.extend(page)
            if len(page) < count or (max_records > 0 and len(results) >= max_records):
                return results[:max_records] if max_records > 0 else results
            offset += count

    def _get_paginated(
        self, path: str, params: dict[str, Any], count: int
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        offset = int(params.get("offset", 0))
        while True:
            params["offset"] = offset
            response = self._request("GET", path, params=params)
            page = response.get("entry", [])
            if not isinstance(page, list):
                raise SplunkClientError("Splunk paginated response is malformed")
            entries.extend(page)
            if len(page) < count:
                return entries
            offset += count

    def _get_json_list(
        self, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        response = self._request("GET", path, params={"output_mode": "json", **(params or {})})
        for key in ("results", "entry", "items", "data"):
            value = response.get(key)
            if isinstance(value, list):
                return value
        raise SplunkClientError(f"Splunk response for {path} did not contain a list")

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        response = None
        for attempt in range(3):
            response = self.session.request(
                method,
                url,
                params=params,
                data=data,
                verify=self.verify_ssl,
                timeout=self.timeout_seconds,
            )
            if response.status_code not in self._RETRY_STATUS_CODES:
                break
            if attempt == 2:
                break
            time.sleep(self._retry_delay(response, attempt))
        if response is None:
            raise SplunkClientError(f"Splunk {method} {path} did not return a response")
        if response.status_code >= 400:
            raise SplunkClientError(
                f"Splunk {method} {path} failed with HTTP {response.status_code}: {response.text}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkClientError(f"Splunk {method} {path} returned non-JSON") from exc
        if not isinstance(payload, dict):
            raise SplunkClientError(f"Splunk {method} {path} returned non-object JSON")
        return payload

    @staticmethod
    def _retry_delay(response: requests.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(float(retry_after), 0.0)
            except ValueError:
                pass
        return float(2**attempt)

    @staticmethod
    def _first_entry_content(response: dict[str, Any]) -> dict[str, Any]:
        entries = response.get("entry")
        if not isinstance(entries, list) or not entries:
            return {}
        content = entries[0].get("content", {})
        return content if isinstance(content, dict) else {}

    @staticmethod
    def _to_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y"}
        return False
