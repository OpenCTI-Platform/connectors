"""Web scan data client of the Silent Push hunt connector."""

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
    text_value,
)

SEARCH_PATH = "/api/v1/merge-api/explore/scandata/search/raw"
PAGE_SIZE = 1000
"""Scans read per request."""


class SilentPushClient(HuntApiClient):
    """Client of the Silent Push web scan data search."""

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Silent Push API.
            api_key: API key.
        """
        super().__init__(base_url=base_url)
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the API key header."""
        return {"X-API-Key": self._api_key}

    def search(self, query: str, limit: int, deadline: RunDeadline) -> HostSearchResult:
        """Search the web scan data with an SPQL query.

        Args:
            query: SPQL query.
            limit: Maximum number of scans read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        hosts: list[Host] = []
        read = 0
        requests = 0
        exhausted = False
        while read < limit:
            size = min(PAGE_SIZE, limit - read)
            requests += 1
            answer = json_object(
                self.hunt_request(
                    "POST",
                    SEARCH_PATH,
                    deadline,
                    "The Silent Push search",
                    params={"limit": size, "skip": read},
                    json={"query": query},
                ),
                "The Silent Push search",
            )
            scans = as_list(as_mapping(answer.get("response")).get("scandata_raw"))
            scans = scans[:size]
            read += len(scans)
            for scan in scans:
                host = silentpush_host(as_mapping(scan))
                if host is not None:
                    hosts.append(host)
            if len(scans) < size:
                exhausted = True
                break
        # A read that stops at the limit never saw the end of the results: more matches may exist
        return HostSearchResult(
            hosts, records=read, more=not exhausted and limit > 0, requests=requests
        )


def silentpush_host(scan: dict[str, Any]) -> Host | None:
    """Map a Silent Push web scan.

    Args:
        scan: Web scan record.

    Returns:
        The host, or ``None`` without an address nor a name.
    """
    host = new_host(scan.get("ip"), scan.get("hostname"))
    if host is None:
        return None
    host.add_domain(scan.get("domain"))
    host.add_port(scan.get("port"))
    ssl = as_mapping(scan.get("ssl"))
    common_name = text_value(as_mapping(ssl.get("subject")).get("common_name"))
    host.add_certificate(
        ssl.get("SHA256"), f"CN={common_name}" if common_name else None
    )
    host.add_fingerprint("jarm", scan.get("jarm"))
    host.add_fingerprint("http.title", scan.get("htmltitle"))
    host.add_fingerprint("http.body_sha256", scan.get("html_body_sha256"))
    host.add_fingerprint("http.server", as_mapping(scan.get("header")).get("server"))
    host.add_url(scan.get("url"))
    host.seen(scan.get("scan_date"))
    return host
