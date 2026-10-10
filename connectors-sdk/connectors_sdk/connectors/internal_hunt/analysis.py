"""Post-processing of hunt results.

Raw telemetry never leaves the connector: the run report only carries counts
and evidence samples (per field, and per hit) whose values are truncated, the
matched values also SHA-256 hashed.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import regex
from connectors_sdk.connectors.internal_hunt.errors import HuntTimeoutError
from connectors_sdk.connectors.internal_hunt.models import (
    HuntEvent,
    HuntEvidence,
    HuntHitEvidence,
    HuntHitField,
    HuntLimits,
    HuntResult,
    HuntTimeWindow,
)
from connectors_sdk.connectors.internal_hunt.timing import RunDeadline

HOST_FIELDS: tuple[str, ...] = (
    "host",
    "hostname",
    "host.name",
    "host.hostname",
    "agent.hostname",
    "computer",
    "computername",
    "devicename",
    "device.hostname",
    "device.name",
    "dvchostname",
    "src_host",
    "dest_host",
    "srchostname",
    "dsthostname",
    "principal.hostname",
    "target.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
)
"""Result fields naming the host of an event, compared case-insensitively."""

DEFAULT_ENTITY_FIELDS: tuple[str, ...] = (
    # Hosts
    "host",
    "hostname",
    "host.name",
    "host.hostname",
    "agent.hostname",
    "dest",
    "dest_host",
    "src_host",
    "computer",
    "computername",
    "devicename",
    "device.hostname",
    "dvchostname",
    "srchostname",
    "dsthostname",
    "principal.hostname",
    "target.hostname",
    "device.name",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    # Users
    "user",
    "username",
    "user.name",
    "src_user",
    "accountname",
    "account",
    "subjectusername",
    "targetusername",
    "userprincipalname",
    "actorusername",
    "principal.user.userid",
    "target.user.userid",
    "actor.user.name",
    # Network peers
    "src",
    "src_ip",
    "dest_ip",
    "source.ip",
    "destination.ip",
    "ipaddress",
    "srcipaddr",
    "dstipaddr",
    "remoteip",
    "principal.ip",
    "target.ip",
    "src_endpoint.ip",
    "dst_endpoint.ip",
)
"""Field names (case-insensitive) identifying hosts, users and network peers."""


@dataclass(frozen=True)
class HitFields:
    """Result fields describing one hit, each by order of preference (case-insensitive).

    Attributes:
        event_id: Fields holding the id of the event on the platform.
        host: Fields naming the host of the event.
        user: Fields naming the user of the event.
        process: Fields naming the process of the event.
    """

    event_id: tuple[str, ...] = ("event.id", "metadata.uid", "_id", "_cd")
    host: tuple[str, ...] = HOST_FIELDS
    user: tuple[str, ...] = (
        "user.name",
        "user",
        "username",
        "src_user",
        "accountname",
        "account",
        "subjectusername",
        "targetusername",
        "userprincipalname",
        "actorusername",
        "actor.user.name",
        "principal.user.userid",
        "target.user.userid",
    )
    process: tuple[str, ...] = (
        "process.executable",
        "process.name",
        "image",
        "newprocessname",
        "processname",
        "process_name",
        "initiatingprocessfilename",
        "actor.process.file.path",
        "process.file.path",
        "process",
    )


DEFAULT_HIT_FIELDS = HitFields()
"""Hit fields of the common field names."""


def flatten_fields(data: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested mappings into dotted field names.

    Args:
        data: Possibly nested event document.
        prefix: Prefix of the field names (used by the recursion).

    Returns:
        A flat mapping, e.g. ``{"process": {"pid": 4}}`` becomes ``{"process.pid": 4}``.
    """
    flat: dict[str, Any] = {}
    for key, value in data.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping) and value:
            flat.update(flatten_fields(value, name))
        else:
            flat[name] = value
    return flat


def value_strings(value: Any) -> list[str]:
    """Return the string forms of a field value.

    Lists yield one string per non-empty element; empty values yield nothing.

    Args:
        value: Raw field value.

    Returns:
        The string values.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [text for item in value for text in value_strings(item)]
    if isinstance(value, Mapping):
        return [json.dumps(value, sort_keys=True, default=str)] if value else []
    if isinstance(value, bool):
        return [str(value).lower()]
    text = str(value).strip()
    return [text] if text else []


def sha256_hex(value: str) -> str:
    """Return the SHA-256 hex digest of a string value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class BenignMatcher:
    """Match result events against the benign patterns of a hunt.

    A pattern is a case-insensitive substring, or a case-insensitive regular
    expression when written between slashes (``/^svc_backup[0-9]+$/``). A pattern
    that is not a valid regular expression is matched as a substring.

    Regular expressions run on the ``regex`` engine, bounded by the run
    deadline: a pattern that backtracks past it stops the run with a timeout
    instead of blocking the report of the run.
    """

    def __init__(self, patterns: Sequence[str], deadline: RunDeadline) -> None:
        """Compile the benign patterns.

        Args:
            patterns: The benign patterns of the hunt.
            deadline: Run deadline bounding the regular expression matching.
        """
        self._deadline = deadline
        self._substrings: list[str] = []
        self._regexes: list[tuple[str, Any]] = []
        for pattern in patterns:
            text = pattern.strip()
            if not text:
                continue
            if len(text) > 2 and text.startswith("/") and text.endswith("/"):
                try:
                    compiled = regex.compile(text[1:-1], regex.IGNORECASE)
                except regex.error:
                    pass
                else:
                    self._regexes.append((text, compiled))
                    continue
            self._substrings.append(text.lower())

    def __bool__(self) -> bool:
        """Return whether at least one pattern is defined."""
        return bool(self._substrings or self._regexes)

    def matches(self, event: HuntEvent) -> bool:
        """Return whether any value of the event matches a benign pattern.

        Args:
            event: Result event.

        Returns:
            True if the event is benign.

        Raises:
            HuntTimeoutError: If a regular expression runs past the run deadline.
        """
        for value in event.fields.values():
            for text in value_strings(value):
                lowered = text.lower()
                if any(sub in lowered for sub in self._substrings):
                    return True
                if any(self._search(item, text) for item in self._regexes):
                    return True
        return False

    def _search(self, item: tuple[str, Any], text: str) -> bool:
        """Search a value with a regular expression within the run deadline."""
        pattern, compiled = item
        try:
            return compiled.search(text, timeout=self._deadline.remaining()) is not None
        except TimeoutError as err:
            raise HuntTimeoutError(
                f"The benign pattern {pattern} did not complete within the run timeout."
            ) from err


def suppress_benign(
    result: HuntResult, patterns: Sequence[str], deadline: RunDeadline
) -> HuntResult:
    """Remove the benign events of a result.

    Suppression applies to the events returned by the platform. When the result
    is truncated, the post-suppression total is unknown whether or not the
    returned events matched (any unreturned event may be benign): the platform
    total is dropped and the hit count is the non-benign returned events, a
    verified lower bound that never inflates escalation or sighting counts.

    Args:
        result: Raw hunt result.
        patterns: Benign patterns of the hunt.
        deadline: Run deadline bounding the regular expression matching.

    Returns:
        The result without benign events.

    Raises:
        HuntTimeoutError: If a regular expression runs past the run deadline.
    """
    matcher = BenignMatcher(patterns, deadline)
    if not matcher:
        return result
    kept = [event for event in result.events if not matcher.matches(event)]
    if len(kept) == len(result.events) and not result.truncated:
        return result
    return HuntResult(events=kept, total_hits=None, truncated=result.truncated)


def _ordered_fields(
    counters: Mapping[str, Counter[str]], priority_fields: Sequence[str]
) -> list[str]:
    """Order the evidence fields: detection fields first, then alphabetically."""
    by_lower = {name.lower(): name for name in counters}
    ordered: dict[str, None] = {}
    for field in priority_fields:
        name = by_lower.get(field.lower())
        if name is not None:
            ordered.setdefault(name, None)
    for name in sorted(counters):
        ordered.setdefault(name, None)
    return list(ordered)


def build_evidence(
    events: Iterable[HuntEvent],
    limits: HuntLimits,
    priority_fields: Sequence[str] = (),
    excluded_fields: Iterable[str] = (),
) -> list[HuntEvidence]:
    """Build the redacted evidence sample of a hunt run.

    Values are counted per field. Fields referenced by the detection come first,
    the most frequent values first, and the sample takes one value per field in
    turn so that it covers as many fields as possible.

    Args:
        events: Result events (after benign suppression).
        limits: Run limits (sample size and preview length).
        priority_fields: Fields sampled first, in order: the fields referenced
            by the detection logic, then the entity fields.
        excluded_fields: Fields never sampled (raw payloads, bookkeeping),
            with their sub-fields.

    Returns:
        At most ``limits.evidence_max_items`` evidence items.
    """
    if limits.evidence_max_items == 0:
        return []
    counters = _count_field_values(events, excluded_fields)
    queues = {
        field: sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        for field, counter in counters.items()
    }
    fields = _ordered_fields(counters, priority_fields)
    picked: list[tuple[str, str, int]] = []
    depth = 0
    while len(picked) < limits.evidence_max_items:
        layer = [
            (field, *queues[field][depth])
            for field in fields
            if depth < len(queues[field])
        ]
        if not layer:
            break
        picked.extend(layer[: limits.evidence_max_items - len(picked)])
        depth += 1
    return [
        HuntEvidence(
            field=field,
            value_hash=sha256_hex(value),
            value_preview=value[: limits.evidence_max_value_length],
            count=count,
        )
        for field, value, count in picked
    ]


def _count_field_values(
    events: Iterable[HuntEvent], excluded_fields: Iterable[str]
) -> dict[str, Counter[str]]:
    """Count the string values of every field of the events."""
    excluded = {name.lower() for name in excluded_fields}
    counters: dict[str, Counter[str]] = {}
    for event in events:
        for field, value in event.fields.items():
            if _is_excluded(field, excluded):
                continue
            texts = value_strings(value)
            if texts:
                counters.setdefault(field, Counter()).update(texts)
    return counters


def evidence_fields(fields: Iterable[str], excluded_fields: Iterable[str]) -> list[str]:
    """Return the fields a hit may report: neither excluded nor under an excluded field.

    Args:
        fields: Fields of a hit (the fields the hunt matched in it).
        excluded_fields: Fields never reported (raw payloads, bookkeeping),
            with their dotted children.

    Returns:
        The fields kept, in their order.
    """
    excluded = {name.lower() for name in excluded_fields}
    return [field for field in fields if not _is_excluded(field, excluded)]


def _is_excluded(field: str, excluded: set[str]) -> bool:
    """Whether a dotted field or one of its parents is excluded (lower-case names)."""
    parts = field.lower().split(".")
    return any(
        ".".join(parts[:depth]) in excluded for depth in range(1, len(parts) + 1)
    )


def present_fields(event: HuntEvent, names: Iterable[str]) -> list[str]:
    """Return the fields of an event among some names, compared case-insensitively.

    Args:
        event: Result event.
        names: Field names, by order of preference.

    Returns:
        The event field names, in the order of ``names``, without duplicates.
    """
    by_lower: dict[str, str] = {}
    for field in event.fields:
        by_lower.setdefault(field.lower(), field)
    found: dict[str, None] = {}
    for name in names:
        present = by_lower.get(name.lower())
        if present is not None:
            found.setdefault(present, None)
    return list(found)


def build_hit_evidence(
    hits: Iterable[tuple[HuntEvent, Sequence[str]]],
    limits: HuntLimits,
    hit_fields: HitFields = DEFAULT_HIT_FIELDS,
) -> list[HuntHitEvidence]:
    """Build the redacted evidence of single hits: what matched, where, by whom and when.

    One item per event, the earliest first (events without time last). A hit
    reports at most ``HIT_MATCHED_FIELDS_MAX`` matched fields, the first ones of
    the hunt logic that hold a value; a matched value is hashed whole and its
    preview truncated. The event id, detection, host, user, process and matched
    field names identify the hit (``hit_key``): each is sent as it is up to
    ``HIT_IDENTITY_MAX_LENGTH`` characters, else as its SHA-256 digest, so the
    evidence of a hit stays bounded and its key never depends on the preview
    length.

    Args:
        hits: Each result event with the fields the hunt matched in it.
        limits: Run limits (number of hits and preview length).
        hit_fields: Fields read for the event id, host, user and process.

    Returns:
        At most ``limits.evidence_max_items`` hits.
    """
    if limits.evidence_max_items == 0:
        return []
    ordered = sorted(
        hits,
        key=lambda hit: (
            hit[0].timestamp is None,
            hit[0].timestamp.timestamp() if hit[0].timestamp else 0.0,
        ),
    )
    return [
        _hit_evidence(event, matched, limits.evidence_max_value_length, hit_fields)
        for event, matched in ordered[: limits.evidence_max_items]
    ]


HIT_KEY_VERSION = "v1"
"""Version of the hit key rule, the first item of the hashed array."""

HIT_MATCHED_FIELDS_MAX = 10
"""Most matched fields one hit reports, the number OpenCTI keeps for a hit."""

HIT_IDENTITY_MAX_LENGTH = 256
"""Longest identity value of a hit (event id, detection, host, user, process, matched field name) sent as it is.

A longer value is sent as ``sha256:<hex digest>``: bounded, never readable in
clear, and still distinct from any other value. OpenCTI stores these values up
to this length at least.
"""


def _identity(value: str | None) -> str | None:
    """Return an identity value of a hit as it is sent (see ``HIT_IDENTITY_MAX_LENGTH``)."""
    if value is None or len(value) <= HIT_IDENTITY_MAX_LENGTH:
        return value
    return f"sha256:{sha256_hex(value)}"


def hit_key(hit: HuntHitEvidence) -> str:
    """Return the stable key of a hit, the one OpenCTI recomputes for the hits it samples.

    The key is the SHA-256 hex digest of a compact JSON array computed over the
    evidence of the hit as it is reported (values exactly as sent, an empty
    string counting as absent):

    - ``["v1", "detection", <detection>]`` when the platform groups the event
      into a detection (the events of one detection are one hit);
    - else ``["v1", "event", <event id>]``;
    - else ``["v1", "fields", <timestamp to the second, UTC, "YYYY-MM-DDTHH:MM:SSZ"
      or "">, <host or "">, <user or "">, <process or "">, [[<field>, <value
      hash, lower case>], ...] sorted]``.

    The security platform is not part of the key: OpenCTI keeps the known hits
    of each hunt per security platform.

    Args:
        hit: Evidence of the hit, as built by ``build_hit_evidence``.

    Returns:
        The key, 64 hexadecimal characters.
    """
    parts: list[Any]
    if hit.detection:
        parts = [HIT_KEY_VERSION, "detection", hit.detection]
    elif hit.event_id:
        parts = [HIT_KEY_VERSION, "event", hit.event_id]
    else:
        timestamp = (
            hit.timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if hit.timestamp
            else ""
        )
        matched = sorted(
            [field.field, field.value_hash.lower()] for field in hit.matched
        )
        parts = [
            HIT_KEY_VERSION,
            "fields",
            timestamp,
            hit.host or "",
            hit.user or "",
            hit.process or "",
            matched,
        ]
    canonical = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def build_hit_keys(
    hits: Iterable[tuple[HuntEvent, Sequence[str]]],
    limits: HuntLimits,
    hit_fields: HitFields = DEFAULT_HIT_FIELDS,
) -> list[str]:
    """Return the distinct keys of every hit read, sampled or not, in the order first met.

    The evidence of each hit is built as for the sample, so the key of a sampled
    hit is the one OpenCTI recomputes from the sample.

    Args:
        hits: Each result event with the fields the hunt matched in it.
        limits: Run limits (preview length).
        hit_fields: Fields read for the event id, host, user and process.

    Returns:
        The distinct hit keys (events of one detection share one key).
    """
    keys = (
        hit_key(
            _hit_evidence(event, matched, limits.evidence_max_value_length, hit_fields)
        )
        for event, matched in hits
    )
    return list(dict.fromkeys(keys))


def _hit_evidence(
    event: HuntEvent, matched: Sequence[str], length: int, hit_fields: HitFields
) -> HuntHitEvidence:
    """Build the evidence of one hit."""
    fields: list[HuntHitField] = []
    for name in matched:
        if len(fields) == HIT_MATCHED_FIELDS_MAX:
            break
        texts = value_strings(event.fields.get(name))
        if texts:
            value = ", ".join(texts)
            fields.append(
                HuntHitField(
                    field=_identity(name),
                    value_hash=sha256_hex(value),
                    value_preview=value[:length],
                )
            )

    def _first(names: Sequence[str]) -> str | None:
        for field in present_fields(event, names):
            texts = value_strings(event.fields[field])
            if texts:
                return texts[0]
        return None

    return HuntHitEvidence(
        event_id=_identity(_first(hit_fields.event_id)),
        timestamp=event.timestamp,
        detection=_identity(event.detection),
        matched=fields,
        host=_identity(_first(hit_fields.host)),
        user=_identity(_first(hit_fields.user)),
        process=_identity(_first(hit_fields.process)),
    )


def count_distinct_entities(
    events: Iterable[HuntEvent], entity_fields: Iterable[str] = DEFAULT_ENTITY_FIELDS
) -> int:
    """Count the distinct hosts, users and network peers hit by a hunt.

    Args:
        events: Result events (after benign suppression).
        entity_fields: Field names identifying entities (case-insensitive).

    Returns:
        The number of distinct entity values.
    """
    names = {name.lower() for name in entity_fields}
    entities: set[str] = set()
    for event in events:
        for field, value in event.fields.items():
            if field.lower() in names:
                entities.update(text.lower() for text in value_strings(value))
    return len(entities)


def event_time_bounds(
    events: Iterable[HuntEvent], window: HuntTimeWindow
) -> tuple[datetime, datetime]:
    """Return the first and last event times, defaulting to the hunt window.

    Args:
        events: Result events.
        window: Time window of the run.

    Returns:
        The (first seen, last seen) datetimes.
    """
    timestamps = [event.timestamp for event in events if event.timestamp is not None]
    if not timestamps:
        return window.start, window.end
    return min(timestamps), max(timestamps)
