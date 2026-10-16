"""Hosts found by infrastructure hunts and their STIX mapping.

The connectors of internet scanning services map every match to a :class:`Host`
(the internet facing IP address or host name, with the domains, certificates
and fingerprints the service holds) and return the hosts of each query as a
:class:`HostSearchResult`.

For a run with hits, :func:`build_infrastructure_objects` produces:

- one ``infrastructure`` named after the hunt and its OpenCTI id, active between
  the first and the last observation of its hosts;
- the IPv4 addresses, domain names and X.509 certificates of the hosts, each
  ``consists-of`` the infrastructure;
- one detection ``indicator`` per observable, ``based-on`` it;
- ``related-to`` relationships from the infrastructure and ``indicates``
  relationships from every indicator to the threats the hunt targets;
- one ``observed-data`` per observable, ``number_observed`` being the number of
  hosts holding it, stamped with the hunt run.

Every object inherits the markings and the author of the hunt. The
infrastructure, its observables, indicators and relationships keep their
deterministic identifiers, so every run of the hunt, on every service, grows
the same infrastructure; the observed-data record what each run observed.
"""

import json
import uuid
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Any

from connectors_sdk.connectors.internal_hunt.errors import HuntExecutionError
from connectors_sdk.connectors.internal_hunt.models import (
    HuntEvent,
    HuntRequest,
    HuntTimeWindow,
)
from connectors_sdk.connectors.internal_hunt.observables import (
    is_public_domain,
    is_public_ip,
)
from connectors_sdk.connectors.internal_hunt.stix_mapping import (
    build_observed_data,
    hunt_author,
    hunt_markings,
)
from connectors_sdk.connectors.internal_hunt.timing import parse_timestamp
from connectors_sdk.models import (
    BaseIdentifiedEntity,
    DomainName,
    Indicator,
    Infrastructure,
    IPV4Address,
    Reference,
    Relationship,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType
from pydantic import Field

CERTIFICATES_FIELD = "certificates"
"""Event field holding the certificates of a host (fingerprint, subject, issuer)."""

IPV4 = "IPv4-Addr"
DOMAIN = "Domain-Name"
CERTIFICATE = "X509-Certificate"
INFRASTRUCTURE_OBSERVABLE_TYPES: tuple[str, ...] = (IPV4, DOMAIN, CERTIFICATE)
"""Observable types infrastructure hunts create."""

OPENCTI_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
"""Namespace of the deterministic identifiers OpenCTI and pycti generate."""


def text_value(value: Any) -> str:
    """Return a value as stripped text (empty for values that are not text or numbers)."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return ""
    return str(value).strip()


def as_mapping(value: Any) -> dict[str, Any]:
    """Return a value when it is a mapping, else an empty one."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """Return a value when it is a list, else an empty one."""
    return value if isinstance(value, list) else []


def parse_asn(value: Any) -> int | None:
    """Parse an autonomous system number (``13335`` or ``AS13335``)."""
    text = text_value(value).upper().removeprefix("AS")
    return int(text) if text.isdigit() else None


def json_object(answer: Any, operation: str) -> dict[str, Any]:
    """Return a JSON object answer.

    Args:
        answer: Decoded answer of a service.
        operation: Description of the call, used in the error message.

    Returns:
        The answer.

    Raises:
        HuntExecutionError: If the answer is not a JSON object.
    """
    if not isinstance(answer, dict):
        raise HuntExecutionError(f"{operation} returned an unexpected answer.")
    return answer


def _append(values: list[Any], value: Any) -> None:
    """Append a value to a list once."""
    if value is not None and value not in values:
        values.append(value)


@dataclass(frozen=True)
class Certificate:
    """An X.509 certificate served by a host.

    Attributes:
        sha256: SHA-256 fingerprint (lower case).
        subject: Subject distinguished name.
        issuer: Issuer distinguished name.
    """

    sha256: str
    subject: str | None = None
    issuer: str | None = None


@dataclass
class Host:
    """An internet host found by an infrastructure hunt.

    Attributes:
        key: Identity of the host (IP address, else host name).
        ip: IP address.
        domains: Domain names of the host.
        asn: Autonomous system number.
        as_name: Autonomous system name.
        ports: Open ports.
        certificates: Certificates served by the host.
        fingerprints: Fingerprint values by event field (``jarm``, ``http.title``...).
        urls: URLs scanned on the host.
        tags: Tags of the service.
        last_seen: Last time the service observed the host.
    """

    key: str
    ip: str | None = None
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
        _append(self.domains, text_value(value).lower().rstrip(".") or None)

    def add_port(self, value: Any) -> None:
        """Add an open port (ignored when not a number)."""
        if isinstance(value, int) and not isinstance(value, bool):
            _append(self.ports, value)
        elif isinstance(value, str) and value.isdigit():
            _append(self.ports, int(value))

    def add_certificate(
        self, sha256: Any, subject: Any = None, issuer: Any = None
    ) -> None:
        """Add a certificate (ignored without a valid SHA-256 fingerprint)."""
        digest = text_value(sha256).lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return
        if all(cert.sha256 != digest for cert in self.certificates):
            self.certificates.append(
                Certificate(
                    digest, text_value(subject) or None, text_value(issuer) or None
                )
            )

    def add_fingerprint(self, name: str, value: Any) -> None:
        """Add a fingerprint value to an event field (ignored when empty)."""
        text = text_value(value)
        if text:
            _append(self.fingerprints.setdefault(name, []), text)

    def add_url(self, value: Any) -> None:
        """Add a scanned URL (ignored when empty)."""
        _append(self.urls, text_value(value) or None)

    def add_tag(self, value: Any) -> None:
        """Add a tag, given as text or as an object with a name."""
        name = value.get("name") if isinstance(value, dict) else value
        _append(self.tags, text_value(name) or None)

    def seen(self, value: Any) -> None:
        """Record an observation time, keeping the most recent."""
        timestamp = parse_timestamp(value)
        if timestamp and (self.last_seen is None or timestamp > self.last_seen):
            self.last_seen = timestamp

    def merge(self, other: "Host") -> None:
        """Merge the data another match holds on the same host."""
        for domain in other.domains:
            self.add_domain(domain)
        self.asn = self.asn if self.asn is not None else other.asn
        self.as_name = self.as_name or other.as_name
        for port in other.ports:
            self.add_port(port)
        for cert in other.certificates:
            self.add_certificate(cert.sha256, cert.subject, cert.issuer)
        for name, values in other.fingerprints.items():
            for value in values:
                self.add_fingerprint(name, value)
        for url in other.urls:
            self.add_url(url)
        for tag in other.tags:
            self.add_tag(tag)
        if other.last_seen:
            self.seen(other.last_seen)

    def fields(self) -> dict[str, Any]:
        """Return the hunt event fields of the host (empty ones left out)."""
        values: dict[str, Any] = {
            "ip": self.ip,
            "domain": list(self.domains),
            "asn": self.asn,
            "as_name": self.as_name,
            "port": list(self.ports),
            "certificate.sha256": [cert.sha256 for cert in self.certificates],
            "certificate.subject": [c.subject for c in self.certificates if c.subject],
            "certificate.issuer": [c.issuer for c in self.certificates if c.issuer],
            CERTIFICATES_FIELD: [asdict(cert) for cert in self.certificates],
            "url": list(self.urls),
            "tag": list(self.tags),
        }
        # A fingerprint named like a certificate field (an issuer without certificate) joins its values
        for name, fingerprint in self.fingerprints.items():
            known = list(values.get(name) or [])
            values[name] = known + [
                value for value in fingerprint if value not in known
            ]
        return {name: value for name, value in values.items() if value}


def new_host(ip: Any = None, hostname: Any = None) -> Host | None:
    """Create the record of a host, keyed by IP address, else by host name.

    Args:
        ip: IP address of the host.
        hostname: Host name of the host, kept as a domain.

    Returns:
        The host, or ``None`` without an address nor a name.
    """
    address = text_value(ip)
    name = text_value(hostname).lower().rstrip(".")
    if not address and not name:
        return None
    host = Host(key=address or name, ip=address or None)
    host.add_domain(name or None)
    return host


@dataclass
class HostSearchResult:
    """Hosts found by one query on an internet scanning service.

    Attributes:
        hosts: Hosts read (at most the requested limit).
        total: Number of matches reported by the service, when it reports one.
        records: Number of records read (hits, scans or IP addresses), whether
            they map to a host or not, when it differs from the number of hosts.
        more: Whether the service holds more matches than it returned, when
            its total is not kept (a total that also counts hosts filtered out).
        requests: Number of search requests sent (pages included).
    """

    hosts: list[Host]
    total: int | None = None
    records: int | None = None
    more: bool = False
    requests: int = 1

    @property
    def read(self) -> int:
        """Number of records the query read from the service."""
        return len(self.hosts) if self.records is None else self.records

    @property
    def truncated(self) -> bool:
        """Whether the service holds more matches than the query read."""
        return self.more or (self.total is not None and self.total > self.read)


def within_window(result: HostSearchResult, window: HuntTimeWindow) -> HostSearchResult:
    """Keep the hosts a service last scanned within the run window.

    Services search their current view of the internet, or whole days: a host
    whose last scan falls outside the window is dropped, and a host without
    scan time is kept. The total of the service also counts hosts outside the
    window: it stays the hit count only when every match was read and kept.
    Once a host is dropped, or when matches were left unread (their scan time
    unknown), only the hosts kept count, and the truncation is kept apart.

    Args:
        result: Hosts found by one query.
        window: Time window of the run.

    Returns:
        The hosts observed within the window.
    """
    hosts = [
        host
        for host in result.hosts
        if host.last_seen is None or window.start <= host.last_seen <= window.end
    ]
    if len(hosts) == len(result.hosts) and not result.truncated:
        return result
    return replace(
        result, hosts=hosts, total=None, records=result.read, more=result.truncated
    )


@dataclass(frozen=True)
class InfrastructureObservable:
    """An observable of the infrastructure.

    Attributes:
        observable_type: ``IPv4-Addr``, ``Domain-Name`` or ``X509-Certificate``.
        value: IP address, domain name or certificate SHA-256 fingerprint.
        subject: Subject of a certificate.
        issuer: Issuer of a certificate.
        count: Number of hosts holding the observable.
    """

    observable_type: str
    value: str
    subject: str | None = None
    issuer: str | None = None
    count: int = field(default=1, compare=False)


def _host_observables(
    fields: Mapping[str, Any], allowed_types: Sequence[str]
) -> Iterator[InfrastructureObservable]:
    """Yield the public IPv4 address, domains and certificates of a host."""
    ip = fields.get("ip")
    if IPV4 in allowed_types and isinstance(ip, str) and is_public_ip(ip) == IPV4:
        yield InfrastructureObservable(IPV4, ip)
    if DOMAIN in allowed_types:
        for domain in fields.get("domain") or []:
            if isinstance(domain, str) and is_public_domain(domain):
                yield InfrastructureObservable(DOMAIN, domain)
    if CERTIFICATE in allowed_types:
        for cert in fields.get(CERTIFICATES_FIELD) or []:
            if isinstance(cert, dict) and cert.get("sha256"):
                yield InfrastructureObservable(
                    CERTIFICATE,
                    str(cert["sha256"]),
                    cert.get("subject"),
                    cert.get("issuer"),
                )


def collect_infrastructure_observables(
    events: Iterable[HuntEvent], allowed_types: Sequence[str], max_items: int
) -> list[InfrastructureObservable]:
    """Collect the observables of the hosts, the most frequent first.

    Args:
        events: Host events of the run.
        allowed_types: Observable types the run may create.
        max_items: Maximum number of observables.

    Returns:
        The observables (public IPv4 addresses and domains only), each with the
        number of hosts holding it; a certificate seen with several subjects or
        issuers keeps the most frequent ones.
    """
    hosts: Counter[tuple[str, str]] = Counter()
    variants: Counter[InfrastructureObservable] = Counter()
    for event in events:
        found = set(_host_observables(event.fields, allowed_types))
        variants.update(found)
        hosts.update({(o.observable_type, o.value) for o in found})
    representatives: dict[tuple[str, str], InfrastructureObservable] = {}
    for observable, _ in sorted(variants.items(), key=lambda item: -item[1]):
        representatives.setdefault(
            (observable.observable_type, observable.value), observable
        )
    ordered = sorted(
        hosts.items(),
        key=lambda item: (
            -item[1],
            INFRASTRUCTURE_OBSERVABLE_TYPES.index(item[0][0]),
            item[0][1],
        ),
    )
    return [
        replace(representatives[key], count=count)
        for key, count in ordered[: max(max_items, 0)]
    ]


def infrastructure_name(hunt_name: str, hunt_id: str) -> str:
    """Name of the infrastructure tracked by a hunt.

    The name carries the immutable OpenCTI id of the hunt next to its display
    name: two hunts sharing a name never grow the same infrastructure.

    Args:
        hunt_name: Name of the hunt.
        hunt_id: OpenCTI internal id of the hunt.

    Returns:
        The hunt name followed by its id.
    """
    return f"{hunt_name} (hunt {hunt_id})"


def infrastructure_stix_id(hunt_id: str) -> str:
    """STIX id of the infrastructure tracked by a hunt, seeded from the hunt id only.

    The name follows the display name of the hunt; the id does not, so the
    runs of a renamed hunt keep growing the same infrastructure (OpenCTI
    matches an incoming object on its STIX id as well as on its name).

    Args:
        hunt_id: OpenCTI internal id of the hunt.

    Returns:
        A deterministic ``infrastructure--`` STIX id.
    """
    seed = json.dumps({"x_opencti_hunt_id": hunt_id}, sort_keys=True)
    return f"infrastructure--{uuid.uuid5(OPENCTI_NAMESPACE, seed)}"


class HuntInfrastructure(Infrastructure):
    """The infrastructure a hunt tracks, identified by the hunt rather than by its name."""

    hunt_id: str = Field(
        description="OpenCTI internal id of the hunt tracking the infrastructure.",
        min_length=1,
        exclude=True,
    )

    def to_stix2_object(self) -> Any:
        """Make the STIX object with the id of the hunt."""
        stix_object = super().to_stix2_object()
        properties = {key: stix_object[key] for key in stix_object}
        properties["id"] = infrastructure_stix_id(self.hunt_id)
        return type(stix_object)(allow_custom=True, **properties)


def build_infrastructure_objects(
    request: HuntRequest,
    hits_count: int,
    first_seen: datetime,
    last_seen: datetime,
    observables: Sequence[InfrastructureObservable],
    fingerprints: str,
    service: str,
) -> list[BaseIdentifiedEntity | dict[str, Any]]:
    """Build the knowledge produced by an infrastructure hunt run.

    Args:
        request: The hunt run request.
        hits_count: Number of hosts found.
        first_seen: First observation of the hosts.
        last_seen: Last observation of the hosts.
        observables: Observables of the hosts.
        fingerprints: Description of the fingerprints of the hunt.
        service: Name of the internet scanning service searched.

    Returns:
        connectors-sdk models and STIX dictionaries (empty without hits).
    """
    if hits_count <= 0:
        return []
    author = hunt_author(request)
    markings = hunt_markings(request) or None
    hunt = request.hunt
    infrastructure = HuntInfrastructure(
        hunt_id=hunt.id,
        name=infrastructure_name(hunt.name, hunt.id),
        description=(
            f"Internet infrastructure matching the fingerprints of the hunt '{hunt.name}' "
            f"({fingerprints}): {hits_count} host(s) found on {service} by hunt run "
            f"{request.hunt_run.id}."
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        author=author,
        markings=markings,
    )
    targets = [Reference(id=target.standard_id) for target in hunt.targets]
    objects: list[BaseIdentifiedEntity | dict[str, Any]] = [infrastructure]
    observations: list[tuple[BaseIdentifiedEntity, int]] = []
    for target in targets:
        objects.append(_relationship("related-to", infrastructure, target, request))
    for observable in observables:
        model = _observable_model(observable, author, markings)
        observations.append((model, observable.count))
        indicator = Indicator(
            name=_indicator_name(observable),
            description=f"Infrastructure tracked by the hunt '{hunt.name}'.",
            pattern=_pattern(observable),
            pattern_type="stix",
            main_observable_type=observable.observable_type,
            valid_from=first_seen,
            author=author,
            markings=markings,
        )
        objects.append(model)
        objects.append(_detection(indicator))
        objects.append(_relationship("consists-of", infrastructure, model, request))
        objects.append(_relationship("based-on", indicator, model, request))
        for target in targets:
            objects.append(_relationship("indicates", indicator, target, request))
    objects.extend(build_observed_data(request, observations, first_seen, last_seen))
    return objects


def _pattern_value(value: str) -> str:
    """Escape a value for a STIX pattern."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(observable: InfrastructureObservable) -> str:
    """Return the STIX pattern detecting an observable."""
    value = _pattern_value(observable.value)
    if observable.observable_type == IPV4:
        return f"[ipv4-addr:value = '{value}']"
    if observable.observable_type == DOMAIN:
        return f"[domain-name:value = '{value}']"
    return f"[x509-certificate:hashes.'SHA-256' = '{value}']"


def _indicator_name(observable: InfrastructureObservable) -> str:
    """Return the name of the indicator of an observable."""
    if observable.observable_type == CERTIFICATE:
        return observable.subject or f"X.509 certificate {observable.value}"
    return observable.value


def _observable_model(
    observable: InfrastructureObservable,
    author: Reference | None,
    markings: list[Any] | None,
) -> BaseIdentifiedEntity:
    """Build the connectors-sdk model of an observable."""
    if observable.observable_type == IPV4:
        return IPV4Address(value=observable.value, author=author, markings=markings)
    if observable.observable_type == DOMAIN:
        return DomainName(value=observable.value, author=author, markings=markings)
    return X509Certificate(
        hashes={HashAlgorithm("SHA-256"): observable.value},
        subject=observable.subject,
        issuer=observable.issuer,
        author=author,
        markings=markings,
    )


def _detection(indicator: Indicator) -> dict[str, Any]:
    """Return the STIX dictionary of an indicator flagged for detection."""
    stix: dict[str, Any] = json.loads(indicator.to_stix2_object().serialize())
    stix["x_opencti_detection"] = True
    return stix


def _relationship(
    relationship_type: str,
    source: BaseIdentifiedEntity | Reference,
    target: BaseIdentifiedEntity | Reference,
    request: HuntRequest,
) -> Relationship:
    """Build a relationship carrying the author and the markings of the hunt."""
    return Relationship(
        type=RelationshipType(relationship_type),
        source=source,
        target=target,
        author=hunt_author(request),
        markings=hunt_markings(request) or None,
    )
