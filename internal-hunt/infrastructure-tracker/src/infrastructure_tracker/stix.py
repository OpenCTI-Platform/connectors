"""STIX mapping of the infrastructure found by a hunt.

For a run with hits, the bundle holds:

- one ``infrastructure`` named after the hunt and its OpenCTI id, active between
  the first and the last observation of its hosts;
- the IPv4 addresses, domain names and X.509 certificates of the hosts, each
  ``consists-of`` the infrastructure;
- one detection ``indicator`` per observable, ``based-on`` it;
- ``related-to`` relationships from the infrastructure and ``indicates``
  relationships from every indicator to the threats the hunt targets;
- one ``observed-data`` per number of hosts, referencing the observables that
  many hosts hold, stamped with the hunt run.

Every object inherits the markings and the author of the hunt. The
infrastructure, its observables, indicators and relationships keep their
standard deterministic identifiers, so every run of the hunt grows the same
infrastructure; the observed-data record what each run observed, with
identifiers scoped to the run.
"""

import json
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntRequest,
    build_observed_data,
    hunt_author,
    hunt_markings,
    is_public_domain,
    is_public_ip,
)
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
from infrastructure_tracker.sources import CERTIFICATES_FIELD

IPV4 = "IPv4-Addr"
DOMAIN = "Domain-Name"
CERTIFICATE = "X509-Certificate"
TRACKED_TYPES: tuple[str, ...] = (IPV4, DOMAIN, CERTIFICATE)
"""Observable types the infrastructure tracker creates."""


@dataclass(frozen=True)
class TrackedObservable:
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
) -> Iterator[TrackedObservable]:
    """Yield the public IPv4 address, domains and certificates of a host."""
    ip = fields.get("ip")
    if IPV4 in allowed_types and isinstance(ip, str) and is_public_ip(ip) == IPV4:
        yield TrackedObservable(IPV4, ip)
    if DOMAIN in allowed_types:
        for domain in fields.get("domain") or []:
            if isinstance(domain, str) and is_public_domain(domain):
                yield TrackedObservable(DOMAIN, domain)
    if CERTIFICATE in allowed_types:
        for cert in fields.get(CERTIFICATES_FIELD) or []:
            if isinstance(cert, dict) and cert.get("sha256"):
                yield TrackedObservable(
                    CERTIFICATE,
                    str(cert["sha256"]),
                    cert.get("subject"),
                    cert.get("issuer"),
                )


def collect_observables(
    events: Iterable[HuntEvent], allowed_types: Sequence[str], max_items: int
) -> list[TrackedObservable]:
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
    variants: Counter[TrackedObservable] = Counter()
    for event in events:
        found = set(_host_observables(event.fields, allowed_types))
        variants.update(found)
        hosts.update({(o.observable_type, o.value) for o in found})
    representatives: dict[tuple[str, str], TrackedObservable] = {}
    for observable, _ in sorted(variants.items(), key=lambda item: -item[1]):
        representatives.setdefault(
            (observable.observable_type, observable.value), observable
        )
    ordered = sorted(
        hosts.items(),
        key=lambda item: (-item[1], TRACKED_TYPES.index(item[0][0]), item[0][1]),
    )
    return [
        replace(representatives[key], count=count)
        for key, count in ordered[: max(max_items, 0)]
    ]


def _pattern_value(value: str) -> str:
    """Escape a value for a STIX pattern."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(observable: TrackedObservable) -> str:
    """Return the STIX pattern detecting an observable."""
    value = _pattern_value(observable.value)
    if observable.observable_type == IPV4:
        return f"[ipv4-addr:value = '{value}']"
    if observable.observable_type == DOMAIN:
        return f"[domain-name:value = '{value}']"
    return f"[x509-certificate:hashes.'SHA-256' = '{value}']"


def _indicator_name(observable: TrackedObservable) -> str:
    """Return the name of the indicator of an observable."""
    if observable.observable_type == CERTIFICATE:
        return observable.subject or f"X.509 certificate {observable.value}"
    return observable.value


def infrastructure_name(hunt_name: str, hunt_id: str) -> str:
    """Name of the infrastructure tracked by a hunt.

    OpenCTI derives the identifier of an infrastructure from its name, so the
    name carries the immutable OpenCTI id of the hunt next to its display name:
    two hunts sharing a name never grow the same infrastructure.

    Args:
        hunt_name: Name of the hunt.
        hunt_id: OpenCTI internal id of the hunt.

    Returns:
        The hunt name followed by the first eight characters of its id.
    """
    return f"{hunt_name} (hunt {hunt_id[:8]})"


def build_infrastructure_objects(
    request: HuntRequest,
    hits_count: int,
    first_seen: datetime,
    last_seen: datetime,
    observables: Sequence[TrackedObservable],
    fingerprints: str,
) -> list[BaseIdentifiedEntity | dict[str, Any]]:
    """Build the knowledge produced by an infrastructure hunt run.

    Args:
        request: The hunt run request.
        hits_count: Number of hosts found.
        first_seen: First observation of the hosts.
        last_seen: Last observation of the hosts.
        observables: Observables of the hosts.
        fingerprints: Description of the fingerprints of the hunt.

    Returns:
        connectors-sdk models and STIX dictionaries (empty without hits).
    """
    if hits_count <= 0:
        return []
    author = hunt_author(request)
    markings = hunt_markings(request) or None
    hunt = request.hunt
    infrastructure = Infrastructure(
        name=infrastructure_name(hunt.name, hunt.id),
        description=(
            f"Internet infrastructure matching the fingerprints of the hunt '{hunt.name}' "
            f"({fingerprints}): {hits_count} host(s) found by hunt run {request.hunt_run.id}."
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


def _observable_model(
    observable: TrackedObservable,
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
