from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

# STIX 2.1 namespace UUID (spec §2.9) for deterministic UUIDv5 IDs.
_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Canonical STIX 2.1 TLP marking-definition IDs (spec §7.2.1.4).
TLP_IDS: dict[str, str] = {
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519f6",
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91ba519f6",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber+strict": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

STAIRWELL_IDENTITY_ID = (
    f"identity--{uuid.uuid5(_STIX_NAMESPACE, 'stairwell-connector-identity')}"
)


def stix_id(stix_type: str, seed: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_STIX_NAMESPACE, seed)}"


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def tlp_marking(tlp: str) -> str:
    return TLP_IDS.get(tlp.lower(), TLP_IDS["amber"])


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
    seed: str,
    abstract: str,
    content: str,
    object_refs: Iterable[str],
    tlp: str,
) -> dict[str, Any]:
    note_id = stix_id("note", seed)
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
    rel_id = stix_id("relationship", f"{relationship_type}|{source_id}|{target_id}")
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
        "id": stix_id("ipv4-addr", value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_ipv6(value: str, tlp: str = "amber") -> dict[str, Any]:
    return {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": stix_id("ipv6-addr", value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_domain(value: str, tlp: str = "amber") -> dict[str, Any]:
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": stix_id("domain-name", value),
        "value": value,
        "object_marking_refs": [tlp_marking(tlp)],
    }


def make_file_by_sha256(
    sha256: str,
    tlp: str = "amber",
    extra: dict[str, Any] | None = None,
    sha1: str | None = None,
    md5: str | None = None,
) -> dict[str, Any]:
    hashes: dict[str, str] = {"SHA-256": sha256}
    if sha1:
        hashes["SHA-1"] = sha1
    if md5:
        hashes["MD5"] = md5
    sco: dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id("file", f"sha256:{sha256.lower()}"),
        "hashes": hashes,
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if extra:
        sco.update(extra)
    return sco


def make_url(value: str, tlp: str = "amber") -> dict[str, Any]:
    return {
        "type": "url",
        "spec_version": "2.1",
        "id": stix_id("url", value),
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
        "id": stix_id("autonomous-system", str(number)),
        "number": int(number),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if name:
        obj["name"] = name
    return obj


def network_observable_for(value: str, kind: str, tlp: str) -> dict[str, Any] | None:
    """Build a STIX SCO for a Stairwell network_indicators entry.

    `kind` is one of: "ip", "hostname", "url".
    """
    if not value:
        return None
    if kind == "ip":
        if ":" in value:
            return make_ipv6(value, tlp=tlp)
        return make_ipv4(value, tlp=tlp)
    if kind == "hostname":
        return make_domain(value, tlp=tlp)
    if kind == "url":
        return make_url(value, tlp=tlp)
    return None


def make_indicator(
    pattern: str,
    name: str,
    seed: str,
    valid_from: str,
    valid_until: str | None = None,
    indicator_types: Iterable[str] = ("malicious-activity",),
    description: str | None = None,
    confidence: int | None = None,
    external_references: list[dict[str, Any]] | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    indicator_id = stix_id("indicator", seed)
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

    `asset_id` is the opaque Stairwell asset token (e.g. `assets/EAGJSW-...`)
    and is the seed for the deterministic UUIDv5 id so re-enrichment of any
    object that this asset has seen reuses the same Identity row.
    """
    ts = now_iso()
    obj: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", f"stairwell-asset|{asset_id}"),
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": ts,
        "modified": ts,
        "name": name or asset_id,
        "identity_class": "system",
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if description:
        obj["description"] = description
    return obj


def make_x509_certificate(
    cert: dict[str, Any], tlp: str = "amber"
) -> dict[str, Any] | None:
    """Map a Stairwell x509Certificate entry to a STIX x509-certificate SCO.

    Stairwell shape: {signature, issuer, subject, earliestValidTime, latestValidTime}.
    The `signature` value is the cert thumbprint and is the deterministic seed.
    """
    signature = cert.get("signature") or ""
    if not signature:
        return None
    obj: dict[str, Any] = {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": stix_id("x509-certificate", f"stairwell-cert|{signature}"),
        "object_marking_refs": [tlp_marking(tlp)],
    }
    if cert.get("subject"):
        obj["subject"] = cert["subject"]
    if cert.get("issuer"):
        obj["issuer"] = cert["issuer"]
    if cert.get("earliestValidTime"):
        obj["validity_not_before"] = cert["earliestValidTime"]
    if cert.get("latestValidTime"):
        obj["validity_not_after"] = cert["latestValidTime"]
    obj["x_stairwell_certificate_signature"] = signature
    return obj


def make_sighting(
    seed: str,
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
    sighting_id = stix_id("sighting", seed)
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
    seed: str,
    name: str,
    object_refs: Iterable[str],
    description: str | None,
    tlp: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    container_id = stix_id(sdo_type, seed)
    ts = now_iso()
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
    seed: str,
    name: str,
    object_refs: Iterable[str],
    description: str | None = None,
    context: str = "malware-analysis",
    tlp: str = "amber",
) -> dict[str, Any]:
    return _container_sdo(
        sdo_type="grouping",
        seed=seed,
        name=name,
        object_refs=object_refs,
        description=description,
        tlp=tlp,
        extra={"context": context},
    )


def make_report(
    seed: str,
    name: str,
    object_refs: Iterable[str],
    published: str,
    description: str | None = None,
    report_types: Iterable[str] = ("threat-report",),
    tlp: str = "amber",
) -> dict[str, Any]:
    return _container_sdo(
        sdo_type="report",
        seed=seed,
        name=name,
        object_refs=object_refs,
        description=description,
        tlp=tlp,
        extra={
            "published": published,
            "report_types": list(report_types),
        },
    )


def bundle(objects: Iterable[dict[str, Any]]) -> str:
    """Serialize a STIX 2.1 bundle to JSON."""
    deduped: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not obj:
            continue
        deduped[obj["id"]] = obj
    payload = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(deduped.values()),
    }
    return json.dumps(payload)
