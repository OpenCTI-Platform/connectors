"""Zetalytics API client wrapper.

Wraps the ``zetalytics`` Python package to provide typed, testable methods
for each endpoint used by the connector.  All methods return the raw
response dictionary from the Zetalytics library so that callers can inspect
the ``results`` list and any metadata without additional parsing here.
"""

from __future__ import annotations

import datetime
from typing import Any

from zetalytics import Zetalytics


class ZetalyticsClient:
    """Thin wrapper around the ``zetalytics`` SDK.

    Each method corresponds to one API endpoint and returns the parsed
    response dict.  On error the underlying library raises; callers should
    handle exceptions at the connector level.
    """

    _DOMAIN_RRTYPES = "a,aaaa,cname,ns,mx,txt,soa_email"

    def __init__(self, token: str, request_timeout: int = 30) -> None:
        self._client = Zetalytics(token=token)
        # The SDK never passes a timeout to individual HTTP requests, which
        # causes the connector to hang indefinitely if the API is slow or
        # unreachable.  Intercept Session.request to enforce a deadline on
        # every call made by the underlying library.
        _request = self._client.requester.request

        def _request_with_timeout(method: str, url: str, **kw: Any) -> Any:
            kw.setdefault("timeout", request_timeout)
            return _request(method, url, **kw)

        self._client.requester.request = _request_with_timeout  # type: ignore[method-assign]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _lookback_start(self, lookback_days: int) -> str:
        """Return an ISO date string for ``lookback_days`` ago."""
        start = datetime.date.today() - datetime.timedelta(days=lookback_days)
        return start.isoformat()

    # ------------------------------------------------------------------
    # Domain / hostname endpoints
    # ------------------------------------------------------------------

    def passive_dns_for_domain(
        self,
        value: str,
        size: int,
        lookback_days: int,
        tsfield: str,
        rrtypes: str = _DOMAIN_RRTYPES,
    ) -> dict[str, Any] | None:
        """Query passive DNS records for a domain or hostname."""
        return self._client.domain2rrtypes(
            q=value,
            rrtypes=rrtypes,
            size=size,
            start=self._lookback_start(lookback_days),
            tsfield=tsfield,
            toBaseDomain=False,
            noSubdomains=False,
        )

    def live_dns(self, value: str) -> dict[str, Any] | None:
        """Perform a live DNS lookup for a domain or hostname."""
        return self._client.liveDNS(q=value)

    def subdomains(self, value: str, max_results: int, active_days: int = 90) -> dict[str, Any] | None:
        """Retrieve known subdomains for a domain."""
        response = self._client.subdomains(
            q=value,
            active=active_days,
            vvv=True,
            sort="last",
        )
        if response and isinstance(response.get("results"), list):
            response["results"] = response["results"][:max_results]
        return response

    def domain_d8s(self, value: str) -> dict[str, Any] | None:
        """Retrieve structured D8S registration context for a domain."""
        return self._client.domain2d8s(q=value)

    def domain_whois(self, value: str, size: int) -> dict[str, Any] | None:
        """Retrieve historical WHOIS records for a domain."""
        return self._client.domain2whois(q=value, size=size)

    def domain_ns_glue(self, value: str) -> dict[str, Any] | None:
        """Retrieve nameserver glue records for a domain."""
        return self._client.domain2nsglue(q=value)

    def ns_to_domains(self, value: str, size: int) -> dict[str, Any] | None:
        """Pivot from a nameserver to domains it serves."""
        return self._client.ns2domain(q=value, size=size)

    def mx_to_domains(self, value: str, size: int) -> dict[str, Any] | None:
        """Pivot from an MX domain to domains it serves."""
        return self._client.mx2domain(q=value, size=size)

    # ------------------------------------------------------------------
    # IP endpoints
    # ------------------------------------------------------------------

    def passive_dns_for_ip(
        self,
        value: str,
        size: int,
        lookback_days: int,
        tsfield: str,
    ) -> dict[str, Any] | None:
        """Query passive DNS records for an IP address, CIDR, or range."""
        return self._client.ip(
            q=value,
            size=size,
            start=self._lookback_start(lookback_days),
            tsfield=tsfield,
        )

    def ip_context(self, value: str) -> dict[str, Any] | None:
        """Retrieve ASN, routing, WHOIS and PTR context for an IP."""
        return self._client.ip2pwhois(q=value)

    def ip_ns_glue(self, value: str) -> dict[str, Any] | None:
        """Retrieve nameserver glue records by IP or CIDR."""
        return self._client.ip2nsglue(q=value)

    # ------------------------------------------------------------------
    # Email pivot endpoints
    # ------------------------------------------------------------------

    def email_address_pivot(self, value: str, size: int) -> dict[str, Any] | None:
        """Pivot on a full registration email address."""
        return self._client.email_address(q=value, size=size)

    def email_domain_pivot(self, value: str, size: int) -> dict[str, Any] | None:
        """Pivot on an email domain."""
        return self._client.email_domain(q=value, size=size)
