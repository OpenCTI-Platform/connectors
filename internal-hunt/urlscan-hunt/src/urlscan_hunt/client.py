"""Search client of the urlscan.io hunt connector."""

from datetime import date
from typing import Any

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

SEARCH_PATH = "/api/v1/search/"
PAGE_SIZE = 100
"""Scans read per request."""


class UrlscanClient(HuntApiClient):
    """Client of the urlscan.io search API."""

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize the client.

        Args:
            base_url: URL of urlscan.io.
            api_key: API key.
        """
        super().__init__(base_url=base_url)
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the API key header."""
        return {"API-Key": self._api_key}

    def search(
        self,
        query: str,
        start: date,
        end: date,
        limit: int,
        deadline: RunDeadline,
    ) -> HostSearchResult:
        """Search the scans of a time window with a urlscan.io query.

        Args:
            query: urlscan.io search query (Elasticsearch query string).
            start: First day of the window.
            end: Last day of the window.
            limit: Maximum number of scans read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        dated = f"({query}) AND date:[{start.isoformat()} TO {end.isoformat()}]"
        hosts: list[Host] = []
        total: int | None = None
        read = 0
        requests = 0
        has_more = False
        search_after: str | None = None
        while read < limit:
            size = min(PAGE_SIZE, limit - read)
            params: dict[str, Any] = {"q": dated, "size": size}
            if search_after:
                params["search_after"] = search_after
            requests += 1
            answer = json_object(
                self.hunt_request(
                    "GET", SEARCH_PATH, deadline, "The urlscan.io search", params=params
                ),
                "The urlscan.io search",
            )
            if isinstance(answer.get("total"), (int, float)):
                total = int(answer["total"])
            results = as_list(answer.get("results"))[:size]
            read += len(results)
            for item in results:
                host = urlscan_host(as_mapping(item))
                if host is not None:
                    hosts.append(host)
            sort = as_list(as_mapping(results[-1]).get("sort")) if results else []
            search_after = ",".join(str(value) for value in sort) or None
            has_more = bool(answer.get("has_more"))
            if not has_more or not search_after:
                break
        # The query is bounded by whole days, so its total also counts scans outside the run window: it is
        # never a hit count, only a sign that matches were left unread (as is `has_more` without a cursor)
        more = has_more or (total is not None and total > read)
        return HostSearchResult(hosts, records=read, more=more, requests=requests)


def urlscan_host(item: dict[str, Any]) -> Host | None:
    """Map a urlscan.io scan.

    Args:
        item: Scan of the search answer.

    Returns:
        The host, or ``None`` without an address nor a domain.
    """
    page = as_mapping(item.get("page"))
    host = new_host(page.get("ip"), page.get("domain"))
    if host is None:
        return None
    host.asn = parse_asn(page.get("asn"))
    host.as_name = text_value(page.get("asnname")) or None
    host.add_fingerprint("http.title", page.get("title"))
    host.add_fingerprint("http.server", page.get("server"))
    # Named like the field certificate_issuer fingerprints match, so the match shows in the evidence
    host.add_fingerprint("certificate.issuer", page.get("tlsIssuer"))
    host.add_url(page.get("url"))
    host.seen(as_mapping(item.get("task")).get("time"))
    return host
