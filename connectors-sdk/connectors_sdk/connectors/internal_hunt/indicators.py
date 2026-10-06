"""Lookups of indicator hunts.

An indicator hunt carries the values to look up (``HuntDefinition.iocs``). The
base connector groups them by observable type into batches of at most
``limits.ioc_batch_size`` values, asks the platform hook for one lookup per batch
and turns the answer into one result per value: seen or not, the number of
events holding it, the first and last of them, and the hosts.

A platform answers a lookup in one of two ways:

- raw events, in which this module finds the values (whole tokens only: a
  domain matches its subdomains, never a longer domain; an address never
  matches inside a longer one), and the fields holding them for the evidence of
  each hit;
- one aggregated row per value (``ioc``, ``hits``, ``first_seen``,
  ``last_seen``, ``hosts``), exact counts computed by the platform itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from connectors_sdk.connectors.internal_hunt.analysis import (
    DEFAULT_HIT_FIELDS,
    HOST_FIELDS,
    HitFields,
    build_hit_keys,
    sha256_hex,
    value_strings,
)
from connectors_sdk.connectors.internal_hunt.models import (
    HuntEvent,
    HuntEvidence,
    HuntIoc,
    HuntIocResult,
    HuntLimits,
    HuntRequest,
)
from connectors_sdk.connectors.internal_hunt.observables import (
    ObservableValue,
    to_observable_model,
)
from connectors_sdk.connectors.internal_hunt.stix_mapping import (
    hunt_author,
    hunt_markings,
)
from connectors_sdk.connectors.internal_hunt.timing import parse_timestamp
from connectors_sdk.models import BaseIdentifiedEntity
from connectors_sdk.models.enums import HashAlgorithm

HOSTS_MAX = 10
"""Hosts kept per value (OpenCTI keeps the same number)."""

AGGREGATED_FIELDS = ("ioc", "hits", "first_seen", "last_seen", "hosts")
"""Fields of an aggregated lookup row, one row per value."""

_TOKEN_BOUNDARIES: dict[str, tuple[str, str]] = {
    "IPv4-Addr": (r"(?<![0-9.])", r"(?![0-9]|\.[0-9])"),
    "IPv6-Addr": (r"(?<![0-9A-Fa-f:])", r"(?![0-9A-Fa-f:])"),
    "Domain-Name": (r"(?<![0-9A-Za-z_-])", r"(?!\.?[0-9A-Za-z_-])"),
    "Hostname": (r"(?<![0-9A-Za-z_-])", r"(?!\.?[0-9A-Za-z_-])"),
    "Email-Addr": (r"(?<![0-9A-Za-z._%+-])", r"(?![0-9A-Za-z.-])"),
    "StixFile": (r"(?<![0-9A-Fa-f])", r"(?![0-9A-Fa-f])"),
    "Mac-Addr": (r"(?<![0-9A-Fa-f:-])", r"(?![0-9A-Fa-f:-])"),
}


@dataclass(frozen=True)
class IocBatch:
    """Values of one observable type looked up by one platform query.

    Attributes:
        observable_type: OpenCTI observable type of every value.
        hash_algorithm: Hash algorithm of file hashes, None for other types.
        iocs: The values.
    """

    observable_type: str
    hash_algorithm: str | None
    iocs: tuple[HuntIoc, ...]

    @property
    def values(self) -> list[str]:
        """Return the values of the batch."""
        return [ioc.value for ioc in self.iocs]


@dataclass
class IocObservation:
    """What a run found for one value."""

    hits: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hosts: list[str] = field(default_factory=list)

    def add(
        self,
        timestamp: datetime | None,
        hosts: Iterable[str],
        count: int = 1,
        last: datetime | None = None,
    ) -> None:
        """Add events holding the value.

        Args:
            timestamp: Time of the (first) event.
            hosts: Hosts of the events.
            count: Number of events.
            last: Time of the last event, the timestamp by default.
        """
        self.hits += max(0, count)
        last = last or timestamp
        if timestamp and (self.first_seen is None or timestamp < self.first_seen):
            self.first_seen = timestamp
        if last and (self.last_seen is None or last > self.last_seen):
            self.last_seen = last
        for host in hosts:
            if host and host not in self.hosts and len(self.hosts) < HOSTS_MAX:
                self.hosts.append(host)

    def merge(self, other: IocObservation) -> None:
        """Add the observation of another lookup of the same value."""
        self.add(other.first_seen, other.hosts, other.hits, other.last_seen)


def batch_iocs(iocs: Sequence[HuntIoc], batch_size: int) -> list[IocBatch]:
    """Group the values of a hunt by observable type, in batches of at most ``batch_size``.

    File hashes are grouped by algorithm as well: platforms store each algorithm
    in its own field.

    Args:
        iocs: Values of the hunt.
        batch_size: Maximum number of values per batch.

    Returns:
        The batches, in the order of the first value of each type.
    """
    size = max(1, batch_size)
    groups: dict[tuple[str, str | None], list[HuntIoc]] = {}
    for ioc in iocs:
        groups.setdefault((ioc.observable_type, ioc.hash_algorithm), []).append(ioc)
    return [
        IocBatch(observable_type, algorithm, tuple(items[start : start + size]))
        for (observable_type, algorithm), items in groups.items()
        for start in range(0, len(items), size)
    ]


def value_pattern(ioc: HuntIoc) -> re.Pattern[str]:
    """Return the pattern finding a value as a whole token in a text.

    URLs are found as substrings, case-sensitively; other values
    case-insensitively, between token boundaries of their type.

    Args:
        ioc: The value.

    Returns:
        The compiled pattern.
    """
    escaped = re.escape(ioc.value)
    if ioc.observable_type == "Url":
        return re.compile(escaped)
    before, after = _TOKEN_BOUNDARIES.get(
        ioc.observable_type, (r"(?<![0-9A-Za-z])", r"(?![0-9A-Za-z])")
    )
    return re.compile(f"{before}{escaped}{after}", re.IGNORECASE)


def event_hosts(
    event: HuntEvent, host_fields: Sequence[str] = HOST_FIELDS
) -> list[str]:
    """Return the hosts an event names, from its host fields."""
    lowered = {name.lower(): value for name, value in event.fields.items()}
    hosts: list[str] = []
    for name in host_fields:
        for host in value_strings(lowered.get(name.lower())):
            if host not in hosts:
                hosts.append(host)
    return hosts


def match_events(
    batch: IocBatch,
    events: Sequence[HuntEvent],
    host_fields: Sequence[str] = HOST_FIELDS,
) -> dict[str, IocObservation]:
    """Find the values of a batch in raw result events.

    Args:
        batch: The values looked up.
        events: Events returned by the platform.
        host_fields: Fields naming the host of an event.

    Returns:
        The observation of each value found, by value key.
    """
    patterns = {ioc.key: value_pattern(ioc) for ioc in batch.iocs}
    observations: dict[str, IocObservation] = {}
    for event in events:
        texts = [
            text for value in event.fields.values() for text in value_strings(value)
        ]
        hosts: list[str] | None = None
        for key, pattern in patterns.items():
            if any(pattern.search(text) for text in texts):
                hosts = event_hosts(event, host_fields) if hosts is None else hosts
                observations.setdefault(key, IocObservation()).add(
                    event.timestamp, hosts
                )
    return observations


def value_hits(
    batch: IocBatch, events: Sequence[HuntEvent]
) -> list[tuple[HuntEvent, list[str]]]:
    """Return the raw result events holding a value of a batch, with the fields holding it.

    Args:
        batch: The values looked up.
        events: Events returned by the platform.

    Returns:
        Each event holding a value, with its fields holding one (in the order of the event).
    """
    patterns = [value_pattern(ioc) for ioc in batch.iocs]
    hits: list[tuple[HuntEvent, list[str]]] = []
    for event in events:
        fields = [
            name
            for name, value in event.fields.items()
            if any(
                pattern.search(text)
                for text in value_strings(value)
                for pattern in patterns
            )
        ]
        if fields:
            hits.append((event, fields))
    return hits


def value_hit_keys(
    batch: IocBatch,
    hits: Sequence[tuple[HuntEvent, Sequence[str]]],
    limits: HuntLimits,
    hit_fields: HitFields = DEFAULT_HIT_FIELDS,
) -> dict[str, list[str]]:
    """Return the keys of the hits holding each value of a batch, by value key.

    The values a hit holds are read in every field of its event, so a value found
    in a field the hit does not report (excluded from the evidence) still has the
    key of the hit; the key derives from the fields the hit reports.

    Args:
        batch: The values looked up.
        hits: The events holding a value, with the fields they report (``value_hits``).
        limits: Run limits (preview length of the hit evidence the keys derive from).
        hit_fields: Fields read for the event id, host, user and process.

    Returns:
        The distinct hit keys of every value found, by value key.
    """
    patterns = {ioc.key: value_pattern(ioc) for ioc in batch.iocs}
    keys: dict[str, dict[str, None]] = {}
    for event, fields in hits:
        texts = [
            text for value in event.fields.values() for text in value_strings(value)
        ]
        [key] = build_hit_keys([(event, fields)], limits, hit_fields)
        for ioc_key, pattern in patterns.items():
            if any(pattern.search(text) for text in texts):
                keys.setdefault(ioc_key, {})[key] = None
    return {ioc_key: list(found) for ioc_key, found in keys.items()}


def aggregated_observations(
    batch: IocBatch, events: Sequence[HuntEvent]
) -> dict[str, IocObservation]:
    """Read aggregated lookup rows, one per value (see ``AGGREGATED_FIELDS``).

    A row naming a value the batch does not hold is ignored.

    Args:
        batch: The values looked up.
        events: Rows returned by the platform.

    Returns:
        The observation of each value found, by value key.
    """
    keys = {ioc.key for ioc in batch.iocs}
    observations: dict[str, IocObservation] = {}
    for event in events:
        key = str(event.fields.get("ioc") or "")
        if key not in keys:
            continue
        try:
            hits = int(float(str(event.fields.get("hits") or 0)))
        except ValueError:
            hits = 0
        if hits <= 0:
            continue
        observations.setdefault(key, IocObservation()).add(
            parse_timestamp(event.fields.get("first_seen")),
            value_strings(event.fields.get("hosts")),
            hits,
            parse_timestamp(event.fields.get("last_seen")),
        )
    return observations


def build_ioc_results(
    iocs: Sequence[HuntIoc],
    observations: Mapping[str, IocObservation],
    unsearched: Mapping[str, str],
    hit_keys: Mapping[str, Sequence[str]] | None = None,
) -> list[HuntIocResult]:
    """Return the result of every value of a run, in the order of the hunt.

    Args:
        iocs: Values of the hunt.
        observations: What was found, by value key.
        unsearched: Why a value was not searched, by value key.
        hit_keys: Keys of the hits holding each value, by value key (``value_hit_keys``);
            None when the lookups return counts instead of events.

    Returns:
        One result per value.
    """
    results: list[HuntIocResult] = []
    for ioc in iocs:
        if ioc.key in unsearched:
            results.append(
                HuntIocResult(key=ioc.key, searched=False, reason=unsearched[ioc.key])
            )
            continue
        observation = observations.get(ioc.key)
        if observation is None or observation.hits <= 0:
            results.append(HuntIocResult(key=ioc.key, seen=False))
            continue
        results.append(
            HuntIocResult(
                key=ioc.key,
                seen=True,
                hits_count=observation.hits,
                first_seen=observation.first_seen,
                last_seen=observation.last_seen,
                hosts=observation.hosts[:HOSTS_MAX],
                hit_keys=(
                    list(hit_keys.get(ioc.key, ())) if hit_keys is not None else None
                ),
            )
        )
    return results


def build_ioc_evidence(
    iocs: Sequence[HuntIoc], results: Sequence[HuntIocResult], limits: HuntLimits
) -> list[HuntEvidence]:
    """Return the evidence of an indicator hunt run: each seen value and its hits, the most seen first."""
    by_key = {ioc.key: ioc for ioc in iocs}
    seen = sorted(
        (result for result in results if result.seen),
        key=lambda result: -result.hits_count,
    )
    return [
        HuntEvidence(
            field=f"ioc.{by_key[result.key].observable_type}",
            value_hash=sha256_hex(by_key[result.key].value),
            value_preview=by_key[result.key].value[: limits.evidence_max_value_length],
            count=result.hits_count,
        )
        for result in seen[: limits.evidence_max_items]
        if result.key in by_key
    ]


def _hash_algorithm(value: str | None) -> HashAlgorithm | None:
    """Return the hash algorithm enum of an OpenCTI algorithm name."""
    return HashAlgorithm(value) if value else None


def build_indicator_objects(
    request: HuntRequest, results: Sequence[HuntIocResult]
) -> list[BaseIdentifiedEntity]:
    """Build the knowledge of an indicator hunt run: the observable of each seen value pasted in the hunt.

    A value coming from indicators or observables already has them in OpenCTI;
    a pasted value is created as an observable, so that OpenCTI can sight it.
    OpenCTI keeps one sighting per hunt, indicator or observable, and Security
    Platform, updated in place from the results and hit keys of each run.

    Args:
        request: The hunt run request.
        results: The result of every value.

    Returns:
        The connectors-sdk models to send to OpenCTI (empty without a seen pasted value or a platform).
    """
    if request.security_platform is None:
        return []
    author = hunt_author(request)
    markings = hunt_markings(request)
    by_key = {ioc.key: ioc for ioc in request.hunt.iocs}
    objects: list[BaseIdentifiedEntity] = []
    for result in results:
        ioc = by_key.get(result.key)
        if not result.seen or ioc is None or ioc.sources:
            continue
        objects.append(
            to_observable_model(
                ObservableValue(
                    ioc.observable_type,
                    ioc.value,
                    _hash_algorithm(ioc.hash_algorithm),
                    result.hits_count,
                ),
                author,
                markings,
            )
        )
    return objects
