from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

import stix2
from connectors_sdk.models import TLPMarking
from pycti import (
    Grouping,
    Identity,
    Indicator,
    Note,
    Report,
    StixCoreRelationship,
    StixSightingRelationship,
)

# IDs are OpenCTI's canonical ones: pycti's type-specific generate_id() for
# SDOs and SROs, and the STIX 2.1 spec's deterministic IDs (computed by the
# stix2 library from each type's ID-contributing properties) for SCOs. The
# same entity imported by another connector therefore gets the same ID.

# TLP marking definitions as the SDK builds them, keyed by level. Every bundle
# carries the definitions its objects reference.
_TLP_OBJECTS: dict[str, dict[str, Any]] = {
    level: json.loads(TLPMarking(level=level).to_stix2_object().serialize())
    for level in ("clear", "white", "green", "amber", "amber+strict", "red")
}
TLP_IDS: dict[str, str] = {level: obj["id"] for level, obj in _TLP_OBJECTS.items()}
# TLP:CLEAR and TLP:WHITE share one ID; a bundle that references it carries
# the CLEAR definition, OpenCTI's current name for that level.
_TLP_BY_ID: dict[str, dict[str, Any]] = {
    obj["id"]: obj for level, obj in _TLP_OBJECTS.items() if level != "white"
}

STAIRWELL_IDENTITY_ID = Identity.generate_id("Stairwell", "organization")


def _sco_id(sco_class: type, **properties: Any) -> str:
    """Spec-deterministic SCO ID (UUIDv5 over the ID-contributing properties)."""
    return sco_class(**properties).id


# Markdown helpers. OpenCTI renders Note content and descriptions as GitHub
# Flavored Markdown, and most values written there come from file contents,
# WHOIS, or DNS, all of which an attacker can choose. Every such value goes
# through one of these so it cannot add links, images, or table cells, or
# break out of the surrounding structure.
_MD_LINE_BREAKS = re.compile(r"[\r\n\v\f\x85\u2028\u2029]+")
_MD_INLINE_SPECIALS = re.compile(r"([\\`*_\[\]<>!|~])")
# A backslash run right before `[`, `]`, or `<` is doubled before the character
# itself is escaped, so the escape always ends with odd parity.
_MD_PROSE_SPECIALS = re.compile(r"(\\*)([\[\]<])")
# GFM turns bare URLs, `www.` hosts, and emails into links without any
# brackets; escaping the character that completes each trigger stops that.
_MD_AUTOLINK = re.compile(r"(?i)(?<=[a-z])(:)(?=//)|(?<=www)(\.)|(@)")
_BACKTICK_RUN = re.compile(r"`+")


def _one_line(value: object) -> str:
    return _MD_LINE_BREAKS.sub(" ", str(value)).strip()


def _defang_autolinks(text: str) -> str:
    return _MD_AUTOLINK.sub(lambda m: "\\" + m.group(0), text)


def _longest_backtick_run(text: str) -> int:
    return max((len(m.group(0)) for m in _BACKTICK_RUN.finditer(text)), default=0)


def md_code(value: object, in_table: bool = False) -> str:
    """Render `value` as a single inline code span.

    Nothing inside a code span is parsed, so this is the default for
    identifiers (hashes, names, paths, rules). The fence is one backtick
    longer than any run in the value; GFM still splits table cells on `|`
    inside code, so pipes are escaped when the span sits in a table.
    """
    text = _one_line(value)
    if not text:
        return ""
    if in_table:
        text = text.replace("|", "\\|")
    fence = "`" * (_longest_backtick_run(text) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_text(value: object) -> str:
    """Render `value` as literal inline text (one line, no markup, no links)."""
    text = _MD_INLINE_SPECIALS.sub(r"\\\1", _one_line(value))
    return _defang_autolinks(text)


def md_fence(value: str) -> str:
    """Render multi-line `value` as a fenced code block it cannot close."""
    fence = "`" * max(3, _longest_backtick_run(value) + 1)
    return f"{fence}\n{value}\n{fence}"


def md_prose(value: str) -> str:
    """Keep markdown formatting in `value` but disable links and images.

    For Stairwell AI triage text, which is markdown by design but can quote
    attacker-chosen strings from the file. Brackets and `<` are escaped (and
    every backslash in a run right before one, so it cannot cancel the
    escape), which
    removes inline links, images, reference definitions, autolinks, and raw
    HTML; bare URLs, `www.` hosts, and emails are defanged. Inside code spans
    the escapes show as literal backslashes.
    """
    text = _MD_PROSE_SPECIALS.sub(lambda m: m.group(1) * 2 + "\\" + m.group(2), value)
    return _defang_autolinks(text)


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def tlp_marking(tlp: str) -> str:
    return TLP_IDS.get(tlp.lower(), TLP_IDS["amber"])


def tlp_marking_object(tlp: str) -> dict[str, Any]:
    """The SDK's marking-definition object for `tlp` (amber if unknown)."""
    return _TLP_OBJECTS.get(tlp.lower(), _TLP_OBJECTS["amber"])


def stairwell_identity() -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": STAIRWELL_IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Stairwell",
        "identity_class": "organization",
        "description": "Stairwell, Inc. — global file corpus and threat intelligence.",
    }


def make_external_reference(
    source_name: str, url: str, description: str | None = None
) -> dict[str, Any]:
    ref = {"source_name": source_name, "url": url}
    if description:
        ref["description"] = description
    return ref


def make_note(
    abstract: str,
    content: str,
    object_refs: Iterable[str],
    tlp: str,
) -> dict[str, Any]:
    """Note whose ID derives from its abstract and content (never a timestamp).

    Content must name its subject (the hash, host, IP, or ASN), or identical
    notes about different observables would share one ID.
    """
    note_id = Note.generate_id(None, content, abstract)
    ts = now_iso()
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "abstract": abstract,
        "content": content,
        "object_refs": list(object_refs),
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_relationship(
    source_id: str,
    target_id: str,
    relationship_type: str = "related-to",
    tlp: str = "amber",
) -> dict[str, Any]:
    rel_id = StixCoreRelationship.generate_id(relationship_type, source_id, target_id)
    ts = now_iso()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_id,
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_ipv4(value: str, tlp: str = "amber") -> dict[str, Any]:
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": _sco_id(stix2.IPv4Address, value=value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_ipv6(value: str, tlp: str = "amber") -> dict[str, Any]:
    return {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": _sco_id(stix2.IPv6Address, value=value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_domain(value: str, tlp: str = "amber") -> dict[str, Any]:
    # DNS names are case-insensitive; one name must be one object.
    value = value.lower()
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": _sco_id(stix2.DomainName, value=value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


_HASH_LENGTHS = {"SHA-256": 64, "SHA-1": 40, "MD5": 32}
_HEX = re.compile(r"[0-9a-fA-F]+")


def valid_hash(algo: str, value: Any) -> bool:
    """True when `value` is a well-formed `algo` digest (hex of the right length).

    Hashes come from API responses; one malformed value in a File SCO makes
    OpenCTI reject the whole bundle it is in.
    """
    length = _HASH_LENGTHS.get(algo)
    return (
        length is not None
        and isinstance(value, str)
        and len(value) == length
        and bool(_HEX.fullmatch(value))
    )


def make_file_by_sha256(
    sha256: str,
    tlp: str = "amber",
    extra: dict[str, Any] | None = None,
    sha1: str | None = None,
    md5: str | None = None,
) -> dict[str, Any]:
    """File SCO keyed by SHA-256; invalid optional hashes are left out."""
    if not valid_hash("SHA-256", sha256):
        raise ValueError(f"not a SHA-256 digest: {sha256!r}")
    sha256 = sha256.lower()
    hashes: dict[str, str] = {"SHA-256": sha256}
    if valid_hash("SHA-1", sha1):
        hashes["SHA-1"] = sha1.lower()
    if valid_hash("MD5", md5):
        hashes["MD5"] = md5.lower()
    sco: dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        # Anchored to SHA-256 alone: the spec's File ID uses the first of MD5,
        # SHA-1, SHA-256 present, so the ID would change whenever an optional
        # hash appears or disappears.
        "id": _sco_id(stix2.File, hashes={"SHA-256": sha256}),
        "hashes": hashes,
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if extra:
        sco.update(extra)
    return sco


_URL_SCHEMES = {"http", "https", "ftp", "ftps"}
_URL_MAX_LENGTH = 2048


def make_url(value: str, tlp: str = "amber") -> dict[str, Any] | None:
    """URL SCO for a well-formed http(s)/ftp(s) URL, or None.

    Values come from strings extracted from files; one malformed `url.value`
    makes OpenCTI reject the whole bundle it is in.
    """
    if (
        not isinstance(value, str)
        or len(value) > _URL_MAX_LENGTH
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        return None
    try:
        parts = urlsplit(value)
        # `port` raises ValueError on a non-numeric or out-of-range port, and
        # port 0 is not one a URL can be fetched from.
        if parts.port == 0:
            return None
    except ValueError:
        return None
    if parts.scheme.lower() not in _URL_SCHEMES or not parts.hostname:
        return None
    return {
        "type": "url",
        "spec_version": "2.1",
        "id": _sco_id(stix2.URL, value=value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_autonomous_system(
    number: int | str,
    name: str | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    obj = {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": _sco_id(stix2.AutonomousSystem, number=int(number)),
        "number": int(number),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if name:
        obj["name"] = name
    return obj


def make_ip(value: str, tlp: str = "amber") -> dict[str, Any] | None:
    """IPv4/IPv6 SCO for a valid address (normalised), or None.

    Values come from strings extracted from files, so `1.2.3.4:80` or free
    text must not become an address SCO.
    """
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if addr.version == 6:
        return make_ipv6(str(addr), tlp=tlp)
    return make_ipv4(str(addr), tlp=tlp)


def network_observable_for(value: str, kind: str, tlp: str) -> dict[str, Any] | None:
    """Build a STIX SCO for a Stairwell network_indicators entry.

    `kind` is one of: "ip", "hostname", "url".
    """
    if not value:
        return None
    if kind == "ip":
        return make_ip(value, tlp=tlp)
    if kind == "hostname":
        return make_domain(value, tlp=tlp)
    if kind == "url":
        return make_url(value, tlp=tlp)
    return None


def make_indicator(
    pattern: str,
    name: str,
    valid_from: str,
    valid_until: str | None = None,
    indicator_types: Iterable[str] = ("malicious-activity",),
    description: str | None = None,
    confidence: int | None = None,
    external_references: list[dict[str, Any]] | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    indicator_id = Indicator.generate_id(pattern)
    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": valid_from,
        "modified": valid_from,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "indicator_types": list(indicator_types),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if valid_until:
        obj["valid_until"] = valid_until
    if description:
        obj["description"] = description
    if confidence is not None:
        obj["confidence"] = int(confidence)
    if external_references:
        obj["external_references"] = list(external_references)
    return obj


def make_based_on_relationship(
    indicator_id: str, target_id: str, tlp: str = "amber"
) -> dict[str, Any]:
    return make_relationship(
        source_id=indicator_id,
        target_id=target_id,
        relationship_type="based-on",
        tlp=tlp,
    )


def make_identity_system(
    asset_id: str,
    name: str | None = None,
    description: str | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    """Identity SDO for a host/asset (identity_class='system').

    Named by the stable Stairwell asset token (e.g. `assets/EAGJSW-...`), so
    the ID (OpenCTI's for that name and class) survives a rename or a response
    without the display name, and two assets sharing a display name stay
    distinct. The display name is kept as an alias.
    """
    ts = now_iso()
    display_name = name if name and name != asset_id else None
    obj: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": Identity.generate_id(asset_id, "system"),
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "name": asset_id,
        "identity_class": "system",
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if display_name:
        obj["x_opencti_aliases"] = [display_name]
    if description:
        obj["description"] = description
    return obj


def make_sighting(
    sighting_of_ref: str,
    where_sighted_refs: Iterable[str],
    first_seen: str,
    last_seen: str,
    count: int,
    confidence: int | None = None,
    description: str | None = None,
    external_references: list[dict[str, Any]] | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    # No first/last seen in the ID: they move on every enrichment, and the
    # sighting of one file on one asset must stay one object.
    sighting_id = StixSightingRelationship.generate_id(
        sighting_of_ref, list(where_sighted_refs)
    )
    ts = now_iso()
    obj: dict[str, Any] = {
        "type": "sighting",
        "spec_version": "2.1",
        "id": sighting_id,
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "count": int(count),
        "sighting_of_ref": sighting_of_ref,
        "where_sighted_refs": list(where_sighted_refs),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if confidence is not None:
        obj["confidence"] = int(confidence)
    if description:
        obj["description"] = description
    if external_references:
        obj["external_references"] = list(external_references)
    return obj


def _container_sdo(
    sdo_type: str,
    container_id: str,
    name: str,
    object_refs: Iterable[str],
    description: str | None,
    tlp: str,
    extra: dict[str, Any] | None = None,
    created: str | None = None,
) -> dict[str, Any]:
    ts = created or now_iso()
    obj: dict[str, Any] = {
        "type": sdo_type,
        "spec_version": "2.1",
        "id": container_id,
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "name": name,
        "object_refs": list(object_refs),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if description:
        obj["description"] = description
    if extra:
        obj.update(extra)
    return obj


def make_grouping(
    name: str,
    object_refs: Iterable[str],
    created: str,
    description: str | None = None,
    context: str = "malware-analysis",
    tlp: str = "amber",
) -> dict[str, Any]:
    """Grouping whose ID derives from name, context, and `created`."""
    return _container_sdo(
        sdo_type="grouping",
        container_id=Grouping.generate_id(name, context, created),
        created=created,
        name=name,
        object_refs=object_refs,
        description=description,
        tlp=tlp,
        extra={"context": context},
    )


def make_report(
    name: str,
    object_refs: Iterable[str],
    published: str,
    description: str | None = None,
    report_types: Iterable[str] = ("threat-report",),
    tlp: str = "amber",
) -> dict[str, Any]:
    return _container_sdo(
        sdo_type="report",
        container_id=Report.generate_id(name, published),
        name=name,
        object_refs=object_refs,
        description=description,
        tlp=tlp,
        extra={
            "published": published,
            "report_types": list(report_types),
        },
    )


def with_markings(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """`objects` plus the TLP marking definitions they reference.

    Without the definition in the bundle, OpenCTI can reject the objects that
    reference it (MISSING_REFERENCE_ERROR).
    """
    out = [obj for obj in objects if obj]
    present = {obj["id"] for obj in out}
    for obj in list(out):
        for ref in obj.get("object_marking_refs") or []:
            if ref in _TLP_BY_ID and ref not in present:
                out.append(_TLP_BY_ID[ref])
                present.add(ref)
    return out


def bundle(objects: Iterable[dict[str, Any]]) -> str:
    """Serialize a STIX 2.1 bundle to JSON, with its TLP marking definitions."""
    deduped: dict[str, dict[str, Any]] = {}
    for obj in with_markings(objects):
        deduped[obj["id"]] = obj
    payload = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(deduped.values()),
    }
    return json.dumps(payload)
