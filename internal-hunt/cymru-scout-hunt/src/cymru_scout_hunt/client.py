"""Search client of the Team Cymru Scout hunt connector."""

from datetime import date
from typing import Any

from connectors_sdk import RateLimit
from connectors_sdk.connectors.internal_hunt import (
    Host,
    HostSearchResult,
    HuntApiClient,
    RunDeadline,
    as_list,
    as_mapping,
    json_object,
    new_host,
    parse_asn,
    text_value,
)

SEARCH_PATH = "/search"
MAX_SIZE = 5000
"""Largest number of IP addresses a search returns."""

FINGERPRINT_TYPES = frozenset({"jarm", "ja4x"})
"""Fingerprint types of Scout kept on the hosts (those fingerprint documents search)."""


class ScoutClient(HuntApiClient):
    """Client of the Team Cymru Scout search API.

    Scout answers 1 request per second: the client paces its requests,
    waiting rather than failing.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Scout API.
            api_key: API key.
        """
        super().__init__(
            base_url=base_url,
            rate_limit=RateLimit(1, "second"),
            raise_on_limit_exceeded=False,
        )
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the token authentication header."""
        return {"Authorization": f"Token {self._api_key}"}

    def search(
        self,
        query: str,
        start: date,
        end: date,
        limit: int,
        deadline: RunDeadline,
    ) -> HostSearchResult:
        """Search the IP addresses matching a Scout query over a time window.

        Args:
            query: Scout query.
            start: First day of the window.
            end: Last day of the window.
            limit: Maximum number of IP addresses read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        size = max(1, min(MAX_SIZE, limit))
        answer = json_object(
            self.hunt_request(
                "GET",
                SEARCH_PATH,
                deadline,
                "The Team Cymru Scout search",
                params={
                    "query": query,
                    "start_date": start.isoformat(),
                    "end_date": end.isoformat(),
                    "size": size,
                },
            ),
            "The Team Cymru Scout search",
        )
        returned = as_list(answer.get("ips"))
        items = returned[:limit]
        hosts = [
            host
            for host in (scout_host(as_mapping(item)) for item in items)
            if host is not None
        ]
        total = answer.get("total")
        if isinstance(total, int) and not isinstance(total, bool):
            return HostSearchResult(hosts, total=total, records=len(items))
        # Without a total, a full page never shows the end of the results: more matches may exist
        return HostSearchResult(hosts, records=len(items), more=len(returned) >= size)


def scout_host(item: dict[str, Any]) -> Host | None:
    """Map a Team Cymru Scout IP address.

    Args:
        item: IP address of the search answer.

    Returns:
        The host, or ``None`` without an address.
    """
    host = new_host(item.get("ip"))
    if host is None:
        return None
    summary = as_mapping(item.get("summary"))
    whois = as_mapping(summary.get("whois"))
    host.asn = parse_asn(whois.get("asn"))
    host.as_name = text_value(whois.get("as_name")) or None
    for record in as_list(summary.get("pdns")):
        host.add_domain(as_mapping(record).get("domain"))
    for port in as_list(summary.get("open_ports")):
        host.add_port(as_mapping(port).get("port"))
    for entry in as_list(summary.get("fingerprints")):
        fingerprint = as_mapping(entry)
        if fingerprint.get("type") in FINGERPRINT_TYPES:
            host.add_fingerprint(str(fingerprint["type"]), fingerprint.get("hash"))
    for tag in as_list(item.get("tags")):
        host.add_tag(tag)
        for child in as_list(as_mapping(tag).get("children")):
            host.add_tag(child)
    host.seen(summary.get("last_seen"))
    return host
