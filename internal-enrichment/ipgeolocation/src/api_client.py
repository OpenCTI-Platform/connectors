"""
IPGeolocation.io OpenCTI Connector — API Client
=================================================

HTTP client for the IPGeolocation.io v3 REST API with:
* Automatic retry + exponential back-off
* Credit-aware single-call vs dedicated-endpoint modes
* Structured logging via the connector helper
"""

from __future__ import annotations

from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import IPIntelligence


class IPGeolocationAPIError(Exception):
    """Raised on non-recoverable API errors."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class IPGeolocationClient:
    """Thread-safe client for IPGeolocation.io v3 endpoints."""

    # Endpoint paths
    _IPGEO = "/v3/ipgeo"
    _SECURITY = "/v3/security"
    _ASN = "/v3/asn"
    _ABUSE = "/v3/abuse"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.ipgeolocation.io",
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: int = 2,
        logger=None,
    ):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._log = logger

        # Build a resilient session
        self._session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    # --------------------------------------------------------------------- #
    # Low-level
    # --------------------------------------------------------------------- #

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """Execute an authenticated GET and return parsed JSON."""
        url = f"{self._base_url}{path}"
        params = params or {}
        params["apiKey"] = self._api_key

        if self._log:
            self._log(f"GET {path} params={_redact(params)}")

        resp = self._session.get(url, params=params, timeout=self._timeout)

        # Log credits charged (header from IPGeolocation)
        credits = resp.headers.get("X-Credits-Charged", "?")
        if self._log:
            self._log(f"  → {resp.status_code} | credits={credits}")

        if resp.status_code == 200:
            return resp.json()

        # Handle known error codes
        body = ""
        try:
            body = resp.json().get("message", resp.text[:300])
        except Exception:
            body = resp.text[:300]

        raise IPGeolocationAPIError(resp.status_code, body)

    # --------------------------------------------------------------------- #
    # Public: single-call mode
    # --------------------------------------------------------------------- #

    def lookup_unified(
        self,
        ip: str,
        include_security: bool = True,
        include_abuse: bool = True,
    ) -> IPIntelligence:
        """Single /v3/ipgeo call with include= for credit efficiency.

        Credits:
            base (geo+asn+company+tz+network) = 1
            +security = +2  (total 3)
            +abuse = +1     (total 4 with security)
        """
        includes: list[str] = []
        if include_security:
            includes.append("security")
        if include_abuse:
            includes.append("abuse")

        params: dict[str, Any] = {"ip": ip}
        if includes:
            params["include"] = ",".join(includes)

        data = self._get(self._IPGEO, params)
        return IPIntelligence.from_ipgeo_response(data)

    # --------------------------------------------------------------------- #
    # Public: dedicated-endpoint mode
    # --------------------------------------------------------------------- #

    def lookup_geo(self, ip: str) -> dict:
        """Geolocation only — 1 credit."""
        return self._get(self._IPGEO, {"ip": ip})

    def lookup_security(self, ip: str) -> dict:
        """Dedicated security endpoint — 2 credits."""
        return self._get(self._SECURITY, {"ip": ip})

    def lookup_asn(self, ip: str) -> dict:
        """ASN details (routes, peers, upstreams) — 1 credit."""
        return self._get(self._ASN, {"ip": ip})

    def lookup_abuse(self, ip: str) -> dict:
        """Abuse contact — 1 credit."""
        return self._get(self._ABUSE, {"ip": ip})

    # --------------------------------------------------------------------- #
    # Public: composite lookup respecting config
    # --------------------------------------------------------------------- #

    def enrich(
        self,
        ip: str,
        *,
        single_call: bool = True,
        use_geo: bool = True,
        use_security: bool = True,
        use_asn: bool = True,
        use_abuse: bool = True,
    ) -> IPIntelligence:
        """High-level entry-point: returns full IPIntelligence.

        When *single_call* is True the connector uses ``/v3/ipgeo`` with
        ``include=security,abuse`` to consolidate HTTP requests.  When
        False it calls each dedicated endpoint separately, which can be
        useful when only some modules are enabled or when the admin
        prefers per-endpoint freshness.
        """
        if single_call and use_geo:
            intel = self.lookup_unified(
                ip,
                include_security=use_security,
                include_abuse=use_abuse,
            )
            # Dedicated ASN is richer (peers, upstreams, routes) than ipgeo.
            if use_asn:
                try:
                    intel.merge_asn(self.lookup_asn(ip))
                except IPGeolocationAPIError:
                    pass  # graceful: keep basic ASN from ipgeo
            return intel

        # Dedicated mode
        intel = IPIntelligence(ip=ip)
        if use_geo:
            try:
                geo = self.lookup_geo(ip)
                intel = IPIntelligence.from_ipgeo_response(geo)
            except IPGeolocationAPIError as exc:
                if self._log:
                    self._log(f"Geo lookup failed: {exc}")
        if use_security:
            try:
                intel.merge_security(self.lookup_security(ip))
            except IPGeolocationAPIError as exc:
                if self._log:
                    self._log(f"Security lookup failed: {exc}")
        if use_asn:
            try:
                intel.merge_asn(self.lookup_asn(ip))
            except IPGeolocationAPIError as exc:
                if self._log:
                    self._log(f"ASN lookup failed: {exc}")
        if use_abuse:
            try:
                intel.merge_abuse(self.lookup_abuse(ip))
            except IPGeolocationAPIError as exc:
                if self._log:
                    self._log(f"Abuse lookup failed: {exc}")
        return intel

    def close(self) -> None:
        self._session.close()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _redact(params: dict) -> dict:
    """Hide the API key in log output."""
    out = dict(params)
    if "apiKey" in out:
        out["apiKey"] = out["apiKey"][:4] + "****"
    return out
