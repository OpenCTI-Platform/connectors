"""Clients of the internet scanning sources searched by infrastructure hunts.

Every client returns :class:`Host` records: the internet facing host (IP address
or host name) with the domains, certificates and fingerprints the source holds.
"""

from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import quote

from connectors_sdk.client.exceptions import ApiNotFoundError
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
    parse_timestamp,
)

CENSYS_PAGE_SIZE = 100
SILENTPUSH_PAGE_SIZE = 1000
URLSCAN_PAGE_SIZE = 100
SCOUT_MAX_SIZE = 5000

CERTIFICATES_FIELD = "certificates"
"""Event field holding the certificates of a host (fingerprint, subject, issuer)."""


@dataclass(frozen=True)
class Certificate:
    """An X.509 certificate served by a host."""

    sha256: str
    subject: str | None = None
    issuer: str | None = None


@dataclass
class Host:
    """An internet host found by a source.

    Attributes:
        key: Identity of the host (IP address, else host name).
        ip: IP address.
        sources: Sources that found the host.
        domains: Domain names of the host.
        asn: Autonomous system number.
        as_name: Autonomous system name.
        ports: Open ports.
        certificates: Certificates served by the host.
        fingerprints: Fingerprint values by kind (``jarm``, ``http.title``...).
        urls: URLs scanned on the host.
        tags: Tags of the sources.
        last_seen: Last time a source observed the host.
    """

    key: str
    ip: str | None = None
    sources: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    asn: int | None = None
    as_name: str | None = None
    ports: list[int] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    fingerprints: dict[str, list[str]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_seen: datetime | None = None

    def add_domain(self, value: Any) -> None:
        """Add a domain name (ignored when empty)."""
        _append(self.domains, _text(value).lower().rstrip(".") or None)

    def add_port(self, value: Any) -> None:
        """Add an open port (ignored when not a number)."""
        if isinstance(value, int) and not isinstance(value, bool):
            _append(self.ports, value)
        elif isinstance(value, str) and value.isdigit():
            _append(self.ports, int(value))

    def add_certificate(
        self, sha256: Any, subject: Any = None, issuer: Any = None
    ) -> None:
        """Add a certificate (ignored without a SHA-256 fingerprint)."""
        digest = _text(sha256).lower()
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            if all(cert.sha256 != digest for cert in self.certificates):
                self.certificates.append(
                    Certificate(digest, _text(subject) or None, _text(issuer) or None)
                )

    def add_fingerprint(self, kind: str, value: Any) -> None:
        """Add a fingerprint value (ignored when empty)."""
        text = _text(value)
        if text:
            _append(self.fingerprints.setdefault(kind, []), text)

    def add_tag(self, value: Any) -> None:
        """Add a tag, given as text or as an object with a name."""
        name = value.get("name") if isinstance(value, dict) else value
        _append(self.tags, _text(name) or None)

    def seen(self, value: Any) -> None:
        """Record an observation time, keeping the most recent."""
        timestamp = parse_timestamp(value)
        if timestamp and (self.last_seen is None or timestamp > self.last_seen):
            self.last_seen = timestamp

    def merge(self, other: "Host") -> None:
        """Merge the data another source holds on the same host."""
        for source in other.sources:
            _append(self.sources, source)
        for domain in other.domains:
            self.add_domain(domain)
        self.asn = self.asn if self.asn is not None else other.asn
        self.as_name = self.as_name or other.as_name
        for port in other.ports:
            self.add_port(port)
        for cert in other.certificates:
            self.add_certificate(cert.sha256, cert.subject, cert.issuer)
        for kind, values in other.fingerprints.items():
            for value in values:
                self.add_fingerprint(kind, value)
        for url in other.urls:
            _append(self.urls, url)
        for tag in other.tags:
            self.add_tag(tag)
        if other.last_seen:
            self.seen(other.last_seen)

    def fields(self) -> dict[str, Any]:
        """Return the hunt event fields of the host."""
        values: dict[str, Any] = {
            "source": list(self.sources),
            "ip": self.ip,
            "domain": list(self.domains),
            "asn": self.asn,
            "as_name": self.as_name,
            "port": list(self.ports),
            "certificate.sha256": [cert.sha256 for cert in self.certificates],
            "certificate.subject": [c.subject for c in self.certificates if c.subject],
            "certificate.issuer": [c.issuer for c in self.certificates if c.issuer],
            CERTIFICATES_FIELD: [asdict(cert) for cert in self.certificates],
            **dict(self.fingerprints),
            "url": list(self.urls),
            "tag": list(self.tags),
        }
        return {name: value for name, value in values.items() if value}


@dataclass
class SourceResult:
    """Hosts found by one source query.

    Attributes:
        hosts: Hosts read (at most the requested limit).
        total: Number of matches reported by the source, when it reports one.
        records: Number of records read (hits, scans or IP addresses), whether
            they map to a host or not, when it differs from the number of hosts.
        more: Whether the source holds more matches than it returned, when
            its total is not kept (a total that also counts hosts filtered out).
    """

    hosts: list[Host]
    total: int | None = None
    records: int | None = None
    more: bool = False

    @property
    def read(self) -> int:
        """Number of records the query read from the source."""
        return len(self.hosts) if self.records is None else self.records

    @property
    def truncated(self) -> bool:
        """Whether the source holds more matches than the query read."""
        return self.more or (self.total is not None and self.total > self.read)


def _text(value: Any) -> str:
    """Return a value as stripped text (empty for non-text values)."""
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ""


def _append(values: list[Any], value: Any) -> None:
    """Append a value to a list once."""
    if value is not None and value not in values:
        values.append(value)


def _dict(value: Any) -> dict[str, Any]:
    """Return a value when it is a mapping, else an empty one."""
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    """Return a value when it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def _asn(value: Any) -> int | None:
    """Parse an autonomous system number (``13335`` or ``AS13335``)."""
    text = _text(value).upper().removeprefix("AS")
    return int(text) if text.isdigit() else None


def _answer(answer: Any, operation: str) -> dict[str, Any]:
    """Return a JSON object answer, rejecting anything else."""
    if not isinstance(answer, dict):
        raise HuntExecutionError(f"{operation} returned an unexpected answer.")
    return answer


def new_host(source: str, ip: Any = None, hostname: Any = None) -> Host | None:
    """Create the record of a host, keyed by IP address, else by host name."""
    address = _text(ip)
    name = _text(hostname).lower().rstrip(".")
    if not address and not name:
        return None
    host = Host(key=address or name, ip=address or None, sources=[source])
    host.add_domain(name or None)
    return host


class CensysClient(HuntApiClient):
    """Client of the Censys Platform global search."""

    def __init__(self, base_url: str, token: str, organisation_id: str | None) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Censys Platform API.
            token: Personal access token.
            organisation_id: Organization ID, if any.
        """
        super().__init__(base_url=base_url)
        self._token = token
        self._organisation_id = organisation_id

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the bearer authentication header."""
        return {"Authorization": f"Bearer {self._token}"}

    def search(self, query: str, limit: int, deadline: RunDeadline) -> SourceResult:
        """Search hosts and web properties with a CenQL query.

        Args:
            query: CenQL query.
            limit: Maximum number of hits read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        params = (
            {"organization_id": self._organisation_id} if self._organisation_id else {}
        )
        hosts: list[Host] = []
        total: int | None = None
        token: str | None = None
        read = 0
        while read < limit:
            body: dict[str, Any] = {
                "query": query,
                "page_size": min(CENSYS_PAGE_SIZE, limit - read),
            }
            if token:
                body["page_token"] = token
            answer = _answer(
                self.hunt_request(
                    "POST",
                    "/v3/global/search/query",
                    deadline,
                    "The Censys search",
                    params=params,
                    json=body,
                ),
                "The Censys search",
            )
            result = _dict(answer.get("result"))
            if isinstance(result.get("total_hits"), (int, float)):
                total = int(result["total_hits"])
            hits = _list(result.get("hits"))[: limit - read]
            read += len(hits)
            for hit in hits:
                host = _censys_host(_dict(hit))
                if host is not None:
                    hosts.append(host)
            token = _text(result.get("next_page_token")) or None
            if not hits or not token:
                break
        return SourceResult(hosts, total, read)


def _censys_host(hit: dict[str, Any]) -> Host | None:
    """Map a Censys host or web property hit."""
    if "host_v1" in hit:
        resource = _dict(_dict(hit["host_v1"]).get("resource"))
        host = new_host("censys", resource.get("ip"))
        if host is None:
            return None
        system = _dict(resource.get("autonomous_system"))
        host.asn = _asn(system.get("asn"))
        host.as_name = _text(system.get("name")) or None
        for name in _list(_dict(resource.get("dns")).get("names")):
            host.add_domain(name)
        for service in _list(resource.get("services")):
            _censys_service(host, _dict(service))
        return host
    resource = _dict(_dict(hit.get("web_property_v1")).get("resource"))
    hostname = _text(resource.get("hostname"))
    if _is_ip(hostname):
        host = new_host("censys", hostname)
    else:
        host = new_host("censys", None, hostname)
    if host is None:
        return None
    host.add_port(resource.get("port"))
    _censys_service(host, resource)
    return host


def _censys_service(host: Host, service: dict[str, Any]) -> None:
    """Map the port, certificate and fingerprints of a Censys service."""
    host.add_port(service.get("port"))
    cert = _dict(service.get("cert"))
    parsed = _dict(cert.get("parsed"))
    host.add_certificate(
        cert.get("fingerprint_sha256"),
        parsed.get("subject_dn"),
        parsed.get("issuer_dn"),
    )
    host.add_fingerprint("ja4x", parsed.get("ja4x"))
    host.add_fingerprint("jarm", _dict(service.get("jarm")).get("fingerprint"))
    host.add_fingerprint("ja4s", _dict(service.get("tls")).get("ja4s"))
    host.add_fingerprint("banner_sha256", service.get("banner_hash_sha256"))
    for endpoint in _list(service.get("endpoints")):
        http = _dict(_dict(endpoint).get("http"))
        host.add_fingerprint("http.title", http.get("html_title"))
        host.add_fingerprint("http.body_sha256", http.get("body_hash_sha256"))
    host.seen(service.get("scan_time"))


def _is_ip(value: str) -> bool:
    """Return whether a host name is an IPv4 address."""
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


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

    def search(self, query: str, limit: int, deadline: RunDeadline) -> SourceResult:
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
        exhausted = False
        while read < limit:
            size = min(SILENTPUSH_PAGE_SIZE, limit - read)
            answer = _answer(
                self.hunt_request(
                    "POST",
                    "/api/v1/merge-api/explore/scandata/search/raw",
                    deadline,
                    "The Silent Push search",
                    params={"limit": size, "skip": read},
                    json={"query": query},
                ),
                "The Silent Push search",
            )
            scans = _list(_dict(answer.get("response")).get("scandata_raw"))[:size]
            read += len(scans)
            for scan in scans:
                host = _silentpush_host(_dict(scan))
                if host is not None:
                    hosts.append(host)
            if len(scans) < size:
                exhausted = True
                break
        # A read that stops at the limit never saw the end of the results: more matches may exist
        return SourceResult(hosts, records=read, more=not exhausted and limit > 0)


def _silentpush_host(scan: dict[str, Any]) -> Host | None:
    """Map a Silent Push web scan."""
    host = new_host("silentpush", scan.get("ip"), scan.get("hostname"))
    if host is None:
        return None
    host.add_domain(scan.get("domain"))
    host.add_port(scan.get("port"))
    ssl = _dict(scan.get("ssl"))
    common_name = _text(_dict(ssl.get("subject")).get("common_name"))
    host.add_certificate(
        ssl.get("SHA256"), f"CN={common_name}" if common_name else None
    )
    host.add_fingerprint("jarm", scan.get("jarm"))
    host.add_fingerprint("http.title", scan.get("htmltitle"))
    host.add_fingerprint("http.body_sha256", scan.get("html_body_sha256"))
    host.add_fingerprint("http.server", _dict(scan.get("header")).get("server"))
    _append(host.urls, _text(scan.get("url")) or None)
    host.seen(scan.get("scan_date"))
    return host


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
    ) -> SourceResult:
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
        search_after: str | None = None
        while read < limit:
            size = min(URLSCAN_PAGE_SIZE, limit - read)
            params: dict[str, Any] = {"q": dated, "size": size}
            if search_after:
                params["search_after"] = search_after
            answer = _answer(
                self.hunt_request(
                    "GET",
                    "/api/v1/search/",
                    deadline,
                    "The urlscan.io search",
                    params=params,
                ),
                "The urlscan.io search",
            )
            if isinstance(answer.get("total"), (int, float)):
                total = int(answer["total"])
            results = _list(answer.get("results"))[:size]
            read += len(results)
            for item in results:
                host = _urlscan_host(_dict(item))
                if host is not None:
                    hosts.append(host)
            sort = _list(_dict(results[-1]).get("sort")) if results else []
            search_after = ",".join(str(value) for value in sort) or None
            if not answer.get("has_more") or not search_after:
                break
        return SourceResult(hosts, total, read)


def _urlscan_host(item: dict[str, Any]) -> Host | None:
    """Map a urlscan.io scan."""
    page = _dict(item.get("page"))
    host = new_host("urlscan", page.get("ip"), page.get("domain"))
    if host is None:
        return None
    host.asn = _asn(page.get("asn"))
    host.as_name = _text(page.get("asnname")) or None
    host.add_fingerprint("http.title", page.get("title"))
    host.add_fingerprint("http.server", page.get("server"))
    host.add_fingerprint("tls.issuer", page.get("tlsIssuer"))
    _append(host.urls, _text(page.get("url")) or None)
    host.seen(_dict(item.get("task")).get("time"))
    return host


class ScoutClient(HuntApiClient):
    """Client of the Team Cymru Scout search API."""

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Scout API.
            api_key: API key.
        """
        super().__init__(base_url=base_url)
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
    ) -> SourceResult:
        """Search the IP addresses matching a Scout query over a time window.

        Args:
            query: Scout query (a fingerprint value, or a query of the Scout language).
            start: First day of the window.
            end: Last day of the window.
            limit: Maximum number of IP addresses read.
            deadline: Run deadline.

        Returns:
            The hosts found.
        """
        size = max(1, min(SCOUT_MAX_SIZE, limit))
        answer = _answer(
            self.hunt_request(
                "GET",
                "/search",
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
        returned = _list(answer.get("ips"))
        items = returned[:limit]
        hosts = []
        for item in items:
            host = _scout_host(_dict(item))
            if host is not None:
                hosts.append(host)
        # A full page never shows the end of the results: more matches may exist
        return SourceResult(hosts, records=len(items), more=len(returned) >= size)


def _scout_host(item: dict[str, Any]) -> Host | None:
    """Map a Team Cymru Scout IP address."""
    host = new_host("cymru_scout", item.get("ip"))
    if host is None:
        return None
    summary = _dict(item.get("summary"))
    whois = _dict(summary.get("whois"))
    host.asn = _asn(whois.get("asn"))
    host.as_name = _text(whois.get("as_name")) or None
    pdns = summary.get("pdns")
    if isinstance(pdns, dict):
        pdns = pdns.get("pdns") or pdns.get("top_pdns")
    for record in _list(pdns):
        host.add_domain(_dict(record).get("domain"))
    open_ports = summary.get("open_ports")
    if isinstance(open_ports, dict):
        open_ports = open_ports.get("top_open_ports")
    for port in _list(open_ports):
        host.add_port(_dict(port).get("port"))
    for tag in _list(item.get("tags")):
        host.add_tag(tag)
    host.seen(summary.get("last_seen"))
    return host


class InternetDbClient(HuntApiClient):
    """Client of Shodan InternetDB (no authentication)."""

    def lookup(self, host: Host, deadline: RunDeadline) -> bool:
        """Add the host names, ports and tags InternetDB holds on a host.

        Args:
            host: Host with an IP address.
            deadline: Run deadline.

        Returns:
            Whether InternetDB knows the IP address.

        Raises:
            HuntExecutionError: If InternetDB cannot be queried.
        """
        try:
            answer = self.hunt_request(
                "GET",
                f"/{quote(host.ip or '', safe='.:')}",
                deadline,
                "The Shodan InternetDB lookup",
                max_timeout=15,
            )
        except HuntExecutionError as err:
            if isinstance(err.__cause__, ApiNotFoundError):
                return False
            raise
        data = _answer(answer, "The Shodan InternetDB lookup")
        for name in _list(data.get("hostnames")):
            host.add_domain(name)
        for port in _list(data.get("ports")):
            host.add_port(port)
        for tag in _list(data.get("tags")):
            host.add_tag(tag)
        return True
