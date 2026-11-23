from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk import ConfigValidationError
from connectors_sdk.exceptions.error import DataRetrievalError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 30
SUMMARIZE_TIMEOUT = 120  # AI File Triage runs an LLM; first call on a hash can be slow.


class StairwellAPIError(DataRetrievalError):
    """A Stairwell request that failed.

    `status` is the HTTP status, or None when no response arrived (a
    transport error such as DNS, TLS, or a timeout).
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class StairwellClient:
    def __init__(
        self,
        api_token: str,
        base_url: str,
        organization_id: str | None = None,
        user_id: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_token:
            raise ConfigValidationError("a Stairwell API token is required")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = self._build_session(api_token, organization_id, user_id)

    @staticmethod
    def _build_session(
        api_token: str, organization_id: str | None, user_id: str | None
    ) -> requests.Session:
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        headers = {
            "Authorization": f"Bearer {api_token}",
            "X-Apikey": api_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if organization_id:
            headers["Organization-Id"] = organization_id
        if user_id:
            headers["User-Id"] = user_id
        session.headers.update(headers)
        return session

    def _get(
        self, path: str, timeout: int | None = None, not_found_ok: bool = True
    ) -> dict[str, Any] | None:
        """GET `path` and return its JSON object.

        Returns None for a 404 when `not_found_ok` (the looked-up entity does
        not exist). Raises `StairwellAPIError` for anything else that is not a
        2xx JSON object: a transport error, an error status, or a body that is
        not JSON or not an object.
        """
        try:
            resp = self._session.get(
                f"{self._base_url}{path}", timeout=timeout or self._timeout
            )
        except requests.RequestException as exc:
            raise StairwellAPIError(f"Stairwell request to {path} failed") from exc
        return self._decode(path, resp, not_found_ok)

    @staticmethod
    def _decode(
        path: str, resp: requests.Response, not_found_ok: bool = True
    ) -> dict[str, Any] | None:
        status = resp.status_code
        if status == 404 and not_found_ok:
            return None
        if status >= 400:
            raise StairwellAPIError(
                f"Stairwell {path} returned status {status}: {resp.text[:200]}",
                status,
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise StairwellAPIError(
                f"Stairwell {path} returned a body that is not JSON", status
            ) from exc
        if not isinstance(body, dict):
            raise StairwellAPIError(
                f"Stairwell {path} returned a JSON {type(body).__name__}, "
                "not an object",
                status,
            )
        return body

    @staticmethod
    def _quote(value: str) -> str:
        return quote(value, safe="")

    # ------------------------------------------------------------------
    # V1 — files (objects)
    # ------------------------------------------------------------------
    def get_object_metadata(self, object_hash: str) -> dict[str, Any] | None:
        return self._get(f"/v1/objects/{self._quote(object_hash)}/metadata")

    def summarize_file(self, object_hash: str) -> dict[str, Any] | None:
        return self._get(
            f"/v1/objects/{self._quote(object_hash)}:summarize",
            timeout=SUMMARIZE_TIMEOUT,
        )

    def list_objects_metadata(
        self,
        cel_filter: str,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> dict[str, Any] | None:
        params = [
            f"filter={self._quote(cel_filter)}",
            f"pageSize={page_size}",
        ]
        if page_token:
            params.append(f"pageToken={self._quote(page_token)}")
        # A listing has no entity to be missing, so a 404 is an error.
        return self._get(f"/v1/objects/metadata?{'&'.join(params)}", not_found_ok=False)

    def get_variants(self, object_hash: str) -> dict[str, Any] | None:
        # XSOAR production pack uses /v202112/variants/{sha256}; the /v1 form
        # exists in some EDR integrations but is not authoritative for variant
        # discovery against the global corpus.
        return self._get(f"/v202112/variants/{self._quote(object_hash)}")

    def list_object_sightings(
        self,
        object_hash: str,
        page_size: int = 100,
        page_token: str | None = None,
    ) -> dict[str, Any] | None:
        params = [f"pageSize={page_size}"]
        if page_token:
            params.append(f"pageToken={self._quote(page_token)}")
        return self._get(
            f"/v1/objects/{self._quote(object_hash)}/sightings?{'&'.join(params)}"
        )

    # ------------------------------------------------------------------
    # V1 — hostnames (DNS history)
    # ------------------------------------------------------------------
    def get_hostname_metadata_v1(self, hostname: str) -> dict[str, Any] | None:
        return self._get(f"/v1/hostnames/{self._quote(hostname)}/metadata")

    # ------------------------------------------------------------------
    # V2 — network intelligence
    # ------------------------------------------------------------------
    def get_hostname_v2(self, hostname: str) -> dict[str, Any] | None:
        return self._get(f"/v2/hostnames/{self._quote(hostname)}")

    def get_hostname_resolutions(
        self,
        hostname: str,
        record_types: str | None = None,
        interval_start: str | None = None,
        interval_end: str | None = None,
        include_errors: bool = False,
    ) -> dict[str, Any] | None:
        params: list[str] = []
        if record_types:
            params.append(f"recordTypes={self._quote(record_types)}")
        if interval_start:
            params.append(f"interval.startTime={self._quote(interval_start)}")
        if interval_end:
            params.append(f"interval.endTime={self._quote(interval_end)}")
        if include_errors:
            params.append("includeErrors=true")
        path = f"/v2/hostnames/{self._quote(hostname)}/resolutions"
        if params:
            path = f"{path}?{'&'.join(params)}"
        return self._get(path)

    def get_hostname_whitelist_status(self, hostname: str) -> dict[str, Any] | None:
        return self._get(f"/v2/hostnames/{self._quote(hostname)}/whitelist-status")

    def get_ip(self, ip: str) -> dict[str, Any] | None:
        return self._get(f"/v2/ips/{self._quote(ip)}")

    def get_ip_whois(self, ip: str, view: str = "FULL") -> dict[str, Any] | None:
        return self._get(f"/v2/ips/{self._quote(ip)}/whois?view={self._quote(view)}")

    def get_ip_hostnames(self, ip: str) -> dict[str, Any] | None:
        return self._get(f"/v2/ips/{self._quote(ip)}/hostnames")

    def get_asn_whois(
        self, asn: str | int, view: str = "FULL"
    ) -> dict[str, Any] | None:
        return self._get(
            f"/v2/asns/{self._quote(str(asn))}/whois?view={self._quote(view)}"
        )

    # ------------------------------------------------------------------
    # UI deep-link helpers (for external_reference)
    # ------------------------------------------------------------------
    def _search_url(self, value: str) -> str:
        return f"{self._base_url}/search?search-query={self._quote(value)}"

    def object_ui_url(self, object_hash: str) -> str:
        return self._search_url(object_hash)

    def hostname_ui_url(self, hostname: str) -> str:
        return self._search_url(hostname)

    def ip_ui_url(self, ip: str) -> str:
        return self._search_url(ip)

    def asn_ui_url(self, asn: str | int) -> str:
        return self._search_url(str(asn))

    def url_ui_url(self, url: str) -> str:
        return self._search_url(url)
