"""Global search client of the Censys Platform hunt connector."""

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

SEARCH_PATH = "/v3/global/search/query"
PAGE_SIZE = 100
"""Largest page of the global search (each page past the first costs a credit)."""


class CensysClient(HuntApiClient):
    """Client of the Censys Platform global search."""

    def __init__(self, base_url: str, token: str, organization_id: str | None) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Censys Platform API.
            token: Personal access token.
            organization_id: Organization whose credits the searches use, if any.
        """
        super().__init__(base_url=base_url)
        self._token = token
        self._organization_id = organization_id

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the bearer authentication header."""
        return {"Authorization": f"Bearer {self._token}"}

    def search(self, query: str, limit: int, deadline: RunDeadline) -> HostSearchResult:
        """Search hosts and web properties with a CenQL query.

        Args:
            query: CenQL query.
            limit: Maximum number of hits read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        params = (
            {"organization_id": self._organization_id} if self._organization_id else {}
        )
        hosts: list[Host] = []
        total: int | None = None
        page_token: str | None = None
        read = 0
        requests = 0
        while read < limit:
            body: dict[str, Any] = {
                "query": query,
                "page_size": min(PAGE_SIZE, limit - read),
            }
            if page_token:
                body["page_token"] = page_token
            requests += 1
            answer = json_object(
                self.hunt_request(
                    "POST",
                    SEARCH_PATH,
                    deadline,
                    "The Censys search",
                    params=params,
                    json=body,
                ),
                "The Censys search",
            )
            result = as_mapping(answer.get("result"))
            if isinstance(result.get("total_hits"), (int, float)):
                total = int(result["total_hits"])
            hits = as_list(result.get("hits"))[: limit - read]
            read += len(hits)
            for hit in hits:
                host = censys_host(as_mapping(hit))
                if host is not None:
                    hosts.append(host)
            page_token = text_value(result.get("next_page_token")) or None
            if not hits or not page_token:
                break
        return HostSearchResult(hosts, total, read, requests=requests)


def censys_host(hit: dict[str, Any]) -> Host | None:
    """Map a Censys host or web property hit.

    Args:
        hit: Hit of the global search.

    Returns:
        The host, or ``None`` without an address nor a name.
    """
    if "host_v1" in hit:
        resource = as_mapping(as_mapping(hit["host_v1"]).get("resource"))
        host = new_host(resource.get("ip"))
        if host is None:
            return None
        system = as_mapping(resource.get("autonomous_system"))
        host.asn = parse_asn(system.get("asn"))
        host.as_name = text_value(system.get("name")) or None
        for name in as_list(as_mapping(resource.get("dns")).get("names")):
            host.add_domain(name)
        for service in as_list(resource.get("services")):
            _add_service(host, as_mapping(service))
        return host
    resource = as_mapping(as_mapping(hit.get("web_property_v1")).get("resource"))
    hostname = text_value(resource.get("hostname"))
    host = new_host(hostname) if _is_ipv4(hostname) else new_host(None, hostname)
    if host is None:
        return None
    _add_service(host, resource)
    return host


def _add_service(host: Host, service: dict[str, Any]) -> None:
    """Map the port, certificate and fingerprints of a Censys service."""
    host.add_port(service.get("port"))
    cert = as_mapping(service.get("cert"))
    parsed = as_mapping(cert.get("parsed"))
    host.add_certificate(
        cert.get("fingerprint_sha256"),
        parsed.get("subject_dn"),
        parsed.get("issuer_dn"),
    )
    host.add_fingerprint("ja4x", parsed.get("ja4x"))
    host.add_fingerprint("jarm", as_mapping(service.get("jarm")).get("fingerprint"))
    host.add_fingerprint("ja4s", as_mapping(service.get("tls")).get("ja4s"))
    host.add_fingerprint("banner_sha256", service.get("banner_hash_sha256"))
    for endpoint in as_list(service.get("endpoints")):
        http = as_mapping(as_mapping(endpoint).get("http"))
        host.add_fingerprint("http.title", http.get("html_title"))
        host.add_fingerprint("http.body_sha256", http.get("body_hash_sha256"))
    host.seen(service.get("scan_time"))


def _is_ipv4(value: str) -> bool:
    """Return whether a host name is an IPv4 address."""
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)
