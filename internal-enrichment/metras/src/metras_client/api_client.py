"""Shared Metras API client.

This module is identical across the metras-feed, metras-enrichment and
metras-stream connectors (copied verbatim — no cross-directory imports).
It wraps the Metras REST API (https://api.metras.sa/api), authenticated with the
``X-API-KEY`` header, and exposes thin methods used by all three connectors.
"""

from collections.abc import Iterator
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class MetrasAPIError(Exception):
    """Raised when the Metras API returns an error or is unreachable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class MetrasClient:
    """Thin HTTP client for the Metras API.

    Methods return parsed JSON (dict) and raise :class:`MetrasAPIError` on
    failure. Parsing of business data belongs in the converters, not here.
    """

    # Conservative default timeouts (connect, read)
    _TIMEOUT = (10, 60)

    def __init__(
        self,
        helper,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
    ) -> None:
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.verify_ssl = verify_ssl

        self.session = requests.Session()
        # Explicit for security scanners; honour the configured value.
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        # Retry on transient/server errors, honouring Retry-After on 429.
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "PATCH", "DELETE"),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ------------------------------------------------------------------ #
    # Low-level request helpers
    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, params=None, json_data=None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method,
                url,
                params=params,
                json=json_data,
                timeout=self._TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            raise MetrasAPIError(f"Request to {path} failed: {exc}") from exc

        self.helper.connector_logger.debug(
            "[API] Request",
            {"method": method, "path": path, "status": resp.status_code},
        )

        if resp.status_code in (401, 403):
            raise MetrasAPIError(
                f"Authentication failed (HTTP {resp.status_code}) for {path}. "
                "Check METRAS_API_KEY.",
                resp.status_code,
            )
        if resp.status_code >= 400:
            raise MetrasAPIError(
                f"Metras API error (HTTP {resp.status_code}) for {path}: "
                f"{resp.text[:500]}",
                resp.status_code,
            )

        # Some write endpoints return 202/empty bodies.
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise MetrasAPIError(
                f"Non-JSON response from {path} (HTTP {resp.status_code}): "
                f"{resp.text[:200]}",
                resp.status_code,
            ) from exc

    def _get(self, path: str, params=None) -> dict:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json_data=None) -> dict:
        return self._request("POST", path, json_data=json_data)

    def _patch(self, path: str, json_data=None) -> dict:
        return self._request("PATCH", path, json_data=json_data)

    def _delete(self, path: str) -> dict:
        return self._request("DELETE", path)

    # ------------------------------------------------------------------ #
    # Connectivity / startup
    # ------------------------------------------------------------------ #
    def ping(self) -> bool:
        """Lightweight connectivity + auth check.

        Metras has no dedicated health endpoint, so a tiny endpoints list call
        is used. Raises :class:`MetrasAPIError` on failure.
        """
        self._get("/v1/endpoints", params={"status": "activated"})
        return True

    # ------------------------------------------------------------------ #
    # Feed (EXTERNAL_IMPORT) endpoints
    # ------------------------------------------------------------------ #
    def list_edr_alerts(self, page_size: int = 50, skip: int = 0, **filters) -> dict:
        """One page of EDR 2.0 alerts. Response: {totalCount, more, data[]}.

        Note: this endpoint has no fromTime/toTime — callers filter client-side
        on ``last_occurrence_time``.
        """
        params = {"limit": page_size, "skip": skip}
        params.update({k: v for k, v in filters.items() if v is not None})
        return self._get("/v1/edr/alerts", params=params)

    def iter_edr_alerts(
        self, page_size: int = 50, max_pages: int = 200, **filters
    ) -> Iterator[dict]:
        """Yield EDR alert records across pages until ``more`` is false."""
        skip = 0
        for _ in range(max_pages):
            payload = self.list_edr_alerts(page_size=page_size, skip=skip, **filters)
            data = payload.get("data") or []
            for record in data:
                yield record
            if not payload.get("more") or not data:
                break
            skip += page_size

    def list_binaries(
        self,
        from_time: str | None = None,
        to_time: str | None = None,
        page_size: int = 50,
        skip: int = 0,
        query: str | None = None,
    ) -> dict:
        """One page of binary inventory. Response: {totalCount, data[]}."""
        params = {"limit": page_size, "skip": skip, "full": "true"}
        if from_time:
            params["fromTime"] = from_time
        if to_time:
            params["toTime"] = to_time
        if query:
            params["query"] = query
        return self._get("/v1/edr/binary/list", params=params)

    def iter_binaries(
        self,
        from_time: str | None = None,
        page_size: int = 50,
        max_pages: int = 200,
        query: str | None = None,
    ) -> Iterator[dict]:
        """Yield binary records across pages (stops when a short page returns)."""
        skip = 0
        for _ in range(max_pages):
            payload = self.list_binaries(
                from_time=from_time, page_size=page_size, skip=skip, query=query
            )
            data = payload.get("data") or []
            for record in data:
                yield record
            if len(data) < page_size:
                break
            skip += page_size

    def binary_details(self, md5: str | None = None, name: str | None = None) -> dict:
        """Single binary by md5 or name."""
        params = {}
        if md5:
            params["md5"] = md5
        if name:
            params["name"] = name
        return self._get("/v1/edr/binary/details", params=params)

    def list_endpoints(self, **filters) -> dict:
        """Endpoint/asset inventory. Response: {endpoints[]}."""
        params = {k: v for k, v in filters.items() if v is not None}
        return self._get("/v1/endpoints", params=params)

    # ------------------------------------------------------------------ #
    # Enrichment (INTERNAL_ENRICHMENT) endpoints
    # ------------------------------------------------------------------ #
    def threat_details(self, **filters) -> dict:
        """Network incident details, filterable by sourceIP/destinationIP/url."""
        params = {k: v for k, v in filters.items() if v is not None}
        return self._get("/v4/threats/detail", params=params)

    def binary_by_hash(
        self, sha256: str | None = None, sha1: str | None = None
    ) -> dict:
        """Look up a binary by sha256/sha1 via the list endpoint's query param."""
        if sha256:
            return self.list_binaries(query=f"sha256:{sha256}")
        if sha1:
            return self.list_binaries(query=f"sha1:{sha1}")
        return {"data": []}

    def alerts_by_agent_ip(self, agent_ip: str, page_size: int = 50) -> dict:
        return self.list_edr_alerts(page_size=page_size, agent_ip=agent_ip)

    # ------------------------------------------------------------------ #
    # Stream (STREAM) endpoints — custom blocklist (file-path only)
    # ------------------------------------------------------------------ #
    def create_blocklist(self, items: list[dict]) -> dict:
        """Create one or more custom blocklists (file_paths). Body is an array."""
        return self._post("/v1/custom-blocklist", json_data=items)

    def list_blocklists(self, name: str | None = None, page_size: int = 50) -> dict:
        params = {"limit": page_size}
        if name:
            params["name"] = name
        return self._get("/v1/custom-blocklist", params=params)

    def update_blocklist(self, blocklist_id: str, patch: dict) -> dict:
        safe_id = quote(str(blocklist_id), safe="")
        return self._patch(f"/v1/custom-blocklist/{safe_id}", json_data=patch)

    def delete_blocklist(self, blocklist_id: str) -> dict:
        safe_id = quote(str(blocklist_id), safe="")
        return self._delete(f"/v1/custom-blocklist/{safe_id}")
