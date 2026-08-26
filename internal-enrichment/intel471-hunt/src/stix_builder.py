"""Build STIX 2.1 bundles from Hunter hunt-package JSON."""

from __future__ import annotations

import logging
import re
import uuid as uuid_lib
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import stix2
from pycti import AttackPattern as PyCtiAttackPattern
from pycti import Campaign as PyCtiCampaign
from pycti import Identity as PyCtiIdentity
from pycti import IntrusionSet as PyCtiIntrusionSet
from pycti import Location as PyCtiLocation
from pycti import Malware as PyCtiMalware
from pycti import Note as PyCtiNote
from pycti import (
    StixCoreRelationship,
)
from pycti import Tool as PyCtiTool
from pycti import Vulnerability as PyCtiVulnerability
from src.severity import severity_to_score
from src.sigma_rule import normalise as normalise_sigma

LOGGER = logging.getLogger(__name__)

AUTHOR_NAME = "Intel 471 — Hunter"
KILL_CHAIN = "mitre-attack"
# Report type applied to every hunt package. A distinct value (rather than the
# generic "threat-report" used by Verity reports) keeps hunt-derived reports
# filterable apart in the OpenCTI UI. `report_types` is an open vocab, so a
# custom value is accepted.
REPORT_TYPES = ["threat-hunting"]
_REFERENCE_SOURCE_LABELS = {
    "general": "Hunter reference",
    "analysis": "Hunter analysis",
    "deep_dives": "Hunter deep dive",
    "blog_links": "Hunter blog",
    "malware_samples": "Hunter malware sample",
}


def build_author() -> stix2.Identity:
    return stix2.Identity(
        id=PyCtiIdentity.generate_id(AUTHOR_NAME, "organization"),
        name=AUTHOR_NAME,
        identity_class="organization",
        description=(
            "Intel 471 Hunter (formerly Cyborg Security Hunter) hunt-package "
            "platform. Hunts ingested into OpenCTI by the intel471-hunt "
            "enrichment connector."
        ),
    )


def build_bundle(
    hunt: dict[str, Any],
    author: stix2.Identity,
    *,
    markings: Optional[list[str]] = None,
    hunter_ui_base_url: Optional[str] = None,
    trigger_entity: Optional[dict[str, Any]] = None,
) -> list[Any]:
    """Return the list of STIX objects for one hunt. The caller bundles them
    together with the shared author Identity.

    Each hunt package is materialised as a **Report** (mirroring the Verity
    report shape) whose ``object_refs`` — the OpenCTI *Entities* tab — carry all
    the context we extract: the sigma **Indicator**, every related SDO
    (attack-patterns, intrusion-sets, campaigns, malware, vulnerabilities,
    tools, sectors, locations) and the relationships between them.

    `trigger_entity` is the OpenCTI entity that the user enriched. When
    supplied, the sigma Indicator is linked directly to it (using its real STIX
    id), the entity is added to the Report's ``object_refs``, and the matching
    auto-generated related entity (if any) is suppressed so we don't create a
    duplicate alongside the user's existing entity.
    """
    objects: list[Any] = []
    hunt_uuid = _hunt_uuid(hunt)
    if not hunt_uuid:
        LOGGER.warning("Hunt %r missing UUID, skipping", hunt.get("title"))
        return objects

    trigger = _normalise_trigger(trigger_entity)

    # Only hunts that ship a sigma rule get an Indicator. OpenCTI validates the
    # pattern with sigmatools and rejects the whole object if it does not parse,
    # so a synthesised placeholder would fail there and take its relationships
    # down with it ("element(s) not found"). The Report still carries the
    # context for a hunt with no rule.
    indicator = (
        _build_indicator(
            hunt,
            hunt_uuid,
            author,
            markings=markings,
            hunter_ui_base_url=hunter_ui_base_url,
        )
        if _sigma_rule(hunt)
        else None
    )
    if indicator is None:
        LOGGER.info(
            "Hunt %r has no sigma rule; emitting the Report without an Indicator",
            hunt.get("title"),
        )

    related = _build_related_entities(hunt, author, markings=markings, skip=trigger)
    relationships = (
        _build_relationships(indicator, related, author, markings=markings)
        if indicator
        else []
    )
    if indicator and trigger and trigger.get("id"):
        relationships.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates", indicator.id, trigger["id"]
                ),
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=trigger["id"],
                created_by_ref=author.id,
                object_marking_refs=markings,
                allow_custom=True,
            )
        )

    object_refs: list[str] = [indicator.id] if indicator else []
    object_refs.extend(obj.id for obj in related)
    object_refs.extend(rel.id for rel in relationships)
    if trigger and trigger.get("id"):
        object_refs.append(trigger["id"])
    # De-dupe while preserving order (a trigger id could coincide with a rel's
    # target, and OpenCTI rejects duplicate object_refs).
    object_refs = list(dict.fromkeys(object_refs))

    report = _build_report(
        hunt,
        hunt_uuid,
        author,
        object_refs,
        markings=markings,
        hunter_ui_base_url=hunter_ui_base_url,
    )

    objects.append(report)
    if indicator:
        objects.append(indicator)
    objects.extend(related)
    objects.extend(relationships)
    objects.extend(_build_notes(hunt, report, author))

    return objects


# Maps the OpenCTI entity_type the user triggered on to the STIX type we'd
# have auto-generated for the same concept, so we can skip the duplicate.
_TRIGGER_TYPE_TO_BUILT = {
    "intrusion-set": "intrusion-set",
    "threat-actor": "intrusion-set",
    "threat-actor-group": "intrusion-set",
    "threat-actor-individual": "intrusion-set",
    "campaign": "campaign",
    "malware": "malware",
    "vulnerability": "vulnerability",
    "attack-pattern": "attack-pattern",
    "tool": "tool",
    "sector": "identity-sector",
    "country": "location-country",
    "region": "location-region",
    "location": "location",
}


def _normalise_trigger(
    trigger_entity: Optional[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    if not trigger_entity:
        return None
    entity_type = (trigger_entity.get("type") or "").lower().replace("_", "-")
    name = trigger_entity.get("name") or ""
    stix_id = trigger_entity.get("id")
    if not stix_id or "--" not in stix_id:
        return None
    if entity_type == "location":
        sub = (
            trigger_entity.get("x_opencti_location_type")
            or trigger_entity.get("location_type")
            or ""
        ).lower()
        built_type = {
            "country": "location-country",
            "region": "location-region",
        }.get(sub)
    else:
        built_type = _TRIGGER_TYPE_TO_BUILT.get(entity_type)
    if not built_type:
        return None
    return {
        "id": stix_id,
        "built_type": built_type,
        "name_lower": name.strip().lower(),
        "mitre_id": (trigger_entity.get("x_mitre_id") or "").upper() or None,
    }


def _trigger_matches(
    trigger: Optional[dict[str, Any]],
    built_type: str,
    name: str,
    mitre_id: Optional[str] = None,
) -> bool:
    if not trigger:
        return False
    if trigger["built_type"] != built_type:
        return False
    if mitre_id and trigger.get("mitre_id"):
        return mitre_id.upper() == trigger["mitre_id"]
    return name.strip().lower() == trigger["name_lower"]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _hunt_uuid(hunt: dict[str, Any]) -> Optional[str]:
    raw = hunt.get("UUID") or hunt.get("uuid") or hunt.get("id")
    if not raw:
        return None
    try:
        return str(uuid_lib.UUID(str(raw))).lower()
    except ValueError:
        LOGGER.warning("Hunt id %r is not a valid UUID", raw)
        return None


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_report(
    hunt: dict[str, Any],
    hunt_uuid: str,
    author: stix2.Identity,
    object_refs: list[str],
    *,
    markings: Optional[list[str]],
    hunter_ui_base_url: Optional[str],
) -> stix2.Report:
    """The hunt package itself. Carries the human-facing context (title,
    description, severity, labels, external references) and, via ``object_refs``,
    everything shown under the OpenCTI Entities tab."""
    published = (
        _parse_date(hunt.get("completed_date"))
        or _parse_date(hunt.get("created_date"))
        or datetime.now(timezone.utc)
    )
    labels = _build_labels(hunt)
    external_references = _build_external_references(
        hunt, hunt_uuid, hunter_ui_base_url
    )

    return stix2.Report(
        id=f"report--{hunt_uuid}",
        name=hunt.get("title") or f"Hunter hunt {hunt_uuid}",
        description=hunt.get("description") or "",
        report_types=REPORT_TYPES,
        published=published,
        object_refs=object_refs,
        created_by_ref=author.id,
        object_marking_refs=markings,
        labels=labels or None,
        external_references=external_references or None,
        allow_custom=True,
        custom_properties={
            "x_opencti_score": severity_to_score(hunt.get("severity")),
        },
    )


def _build_indicator(
    hunt: dict[str, Any],
    hunt_uuid: str,
    author: stix2.Identity,
    *,
    markings: Optional[list[str]],
    hunter_ui_base_url: Optional[str],
) -> stix2.Indicator:
    """The sigma detection. Kept lean — the surrounding context lives on the
    Report. Carries the severity label + score and a back-link to the hunt."""
    valid_from = (
        _parse_date(hunt.get("completed_date"))
        or _parse_date(hunt.get("created_date"))
        or datetime.now(timezone.utc)
    )
    sigma_pattern = _sigma_rule(hunt)
    sev = hunt.get("severity")
    labels = [f"severity:{str(sev).lower()}"] if sev else None
    ui_ref = _hunter_ui_reference(hunt_uuid, hunter_ui_base_url)

    return stix2.Indicator(
        id=f"indicator--{hunt_uuid}",
        name=hunt.get("title") or f"Hunter hunt {hunt_uuid}",
        description=hunt.get("description") or "",
        pattern=sigma_pattern,
        pattern_type="sigma",
        valid_from=valid_from,
        created_by_ref=author.id,
        object_marking_refs=markings,
        labels=labels,
        external_references=[ui_ref] if ui_ref else None,
        allow_custom=True,
        custom_properties={
            "x_opencti_score": severity_to_score(hunt.get("severity")),
        },
    )


def _sigma_rule(hunt: dict[str, Any]) -> str:
    """The hunt's sigma rule, or an empty string when it ships none.

    The rule is normalised first (see `src.sigma_rule`): OpenCTI parses the
    pattern with pySigma and rejects an Indicator whose rule does not parse,
    which then breaks every relationship that points at it. Never synthesise a
    stand-in for a hunt that ships no rule.
    """
    sigma = hunt.get("sigma")
    if not isinstance(sigma, str):
        return ""
    return normalise_sigma(sigma)


def _build_labels(hunt: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()

    def _add(value: Optional[str]) -> None:
        if not value:
            return
        norm = str(value).strip()
        if not norm or norm.lower() in seen:
            return
        seen.add(norm.lower())
        labels.append(norm)

    sev = hunt.get("severity")
    if sev:
        _add(f"severity:{str(sev).lower()}")

    tags = hunt.get("tags") or {}
    for key in (
        "threat_categories",
        "kill_chains",
        "attack_surfaces",
        "target_oses",
        "threat_types",
        "platform_types",
        "goals",
        "motivations",
    ):
        for item in tags.get(key) or []:
            _add(item)

    # Promote unaffiliated threat_names (those that won't become Malware) to labels.
    if "Malware" not in (tags.get("threat_categories") or []):
        for item in tags.get("threat_names") or []:
            _add(f"threat:{item}")

    return labels


def _hunter_ui_reference(
    hunt_uuid: str, hunter_ui_base_url: Optional[str]
) -> Optional[stix2.ExternalReference]:
    """Back-link to the hunt in the Hunter UI, or None if no UI base configured."""
    if not hunter_ui_base_url:
        return None
    return stix2.ExternalReference(
        source_name="Intel 471 Hunter",
        url=f"{hunter_ui_base_url.rstrip('/')}/hunts/{hunt_uuid}",
        external_id=hunt_uuid,
    )


def _build_external_references(
    hunt: dict[str, Any], hunt_uuid: str, hunter_ui_base_url: Optional[str]
) -> list[stix2.ExternalReference]:
    refs: list[stix2.ExternalReference] = []
    ui_ref = _hunter_ui_reference(hunt_uuid, hunter_ui_base_url)
    if ui_ref:
        refs.append(ui_ref)
    references = hunt.get("references") or {}
    for bucket, label in _REFERENCE_SOURCE_LABELS.items():
        for url in references.get(bucket) or []:
            if not url:
                continue
            refs.append(stix2.ExternalReference(source_name=label, url=url))
    return refs


def _build_notes(
    hunt: dict[str, Any],
    report: stix2.Report,
    author: stix2.Identity,
) -> list[stix2.Note]:
    notes: list[stix2.Note] = []
    response_actions = hunt.get("response_actions") or {}

    sections = [
        ("Analyst runbook", response_actions.get("analyst_runbook")),
        (
            "Mitigation recommendations",
            response_actions.get("mitigation_recommendations"),
        ),
        ("Validation", hunt.get("validation")),
    ]
    base_created = (
        _parse_date(hunt.get("last_updated"))
        or _parse_date(hunt.get("completed_date"))
        or _parse_date(hunt.get("created_date"))
        or datetime.now(timezone.utc)
    )
    for abstract, content in sections:
        if not content:
            continue
        notes.append(
            stix2.Note(
                id=PyCtiNote.generate_id(base_created.isoformat(), content),
                abstract=abstract,
                content=content,
                created=base_created,
                modified=base_created,
                created_by_ref=author.id,
                object_refs=[report.id],
                allow_custom=True,
            )
        )

    for entry in hunt.get("running_analyst_notes") or []:
        content = entry.get("current_analyst_note")
        if not content:
            continue
        created = _parse_date(entry.get("analyst_note_date")) or base_created
        abstract = entry.get("analyst_note_type") or "Analyst note"
        notes.append(
            stix2.Note(
                id=PyCtiNote.generate_id(created.isoformat(), content),
                abstract=abstract,
                content=content,
                created=created,
                modified=created,
                created_by_ref=author.id,
                object_refs=[report.id],
                allow_custom=True,
            )
        )
    return notes


def _build_related_entities(
    hunt: dict[str, Any],
    author: stix2.Identity,
    *,
    markings: Optional[list[str]],
    skip: Optional[dict[str, Any]] = None,
) -> list[Any]:
    objects: list[Any] = []
    seen_ids: set[str] = set()

    def _push(obj: Any) -> None:
        if obj.id not in seen_ids:
            seen_ids.add(obj.id)
            objects.append(obj)

    tags = hunt.get("tags") or {}
    mapping = hunt.get("mapping") or {}
    mitre = mapping.get("mitre") or {}

    for attack_pattern, mitre_id in _attack_patterns_from_mitre(
        mitre, author, markings
    ):
        if _trigger_matches(skip, "attack-pattern", attack_pattern.name, mitre_id):
            continue
        _push(attack_pattern)

    for name in tags.get("actors") or []:
        if _trigger_matches(skip, "intrusion-set", name):
            continue
        _push(_build_intrusion_set(name, author, markings))

    for name in tags.get("campaigns") or []:
        if _trigger_matches(skip, "campaign", name):
            continue
        _push(_build_campaign(name, author, markings))

    if "Malware" in (tags.get("threat_categories") or []):
        for name in tags.get("threat_names") or []:
            if _trigger_matches(skip, "malware", name):
                continue
            _push(_build_malware(name, author, markings))

    vuln_names = set(tags.get("exploit_or_vulns") or [])
    vuln_names.update(mapping.get("exploit_or_vulns") or [])
    for name in vuln_names:
        if _trigger_matches(skip, "vulnerability", name):
            continue
        _push(_build_vulnerability(name, author, markings))

    tool_names: set[str] = set(tags.get("tools") or [])
    tool_names.update(tags.get("tooling") or [])
    for name in tool_names:
        if _trigger_matches(skip, "tool", name):
            continue
        _push(_build_tool(name, author, markings))

    for name in tags.get("target_industries") or []:
        if _trigger_matches(skip, "identity-sector", name):
            continue
        _push(_build_sector(name, author, markings))

    country_names: set[str] = set(tags.get("target_countries") or [])
    country_names.update(tags.get("source_countries") or [])
    for name in country_names:
        if _trigger_matches(skip, "location-country", name):
            continue
        _push(_build_country(name, author, markings))

    region_names: set[str] = set(tags.get("target_regions") or [])
    region_names.update(tags.get("source_regions") or [])
    for name in region_names:
        if _trigger_matches(skip, "location-region", name):
            continue
        _push(_build_region(name, author, markings))

    return objects


def _attack_patterns_from_mitre(
    mitre: dict[str, Any], author: stix2.Identity, markings: Optional[list[str]]
) -> Iterable[tuple[stix2.AttackPattern, str]]:
    payload = mitre.get("mitre_attack_payload") or []
    # payload entries look like [{ "T1059.007": {"technique_name": ..., "tactics": [...]}}, ...]
    seen: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for tech_id, body in entry.items():
            if tech_id in seen:
                continue
            seen.add(tech_id)
            name = (body or {}).get("technique_name") or tech_id
            tactics = (body or {}).get("tactics") or []
            yield _build_attack_pattern(
                tech_id, name, tactics, author, markings
            ), tech_id

    # Fallback: if payload empty but technique_ids/names are populated, still emit them.
    if not payload:
        ids = mitre.get("mitre_attack_technique_ids") or []
        names = mitre.get("mitre_attack_techniques") or []
        for idx, tech_id in enumerate(ids):
            if tech_id in seen:
                continue
            seen.add(tech_id)
            name = names[idx] if idx < len(names) else tech_id
            yield _build_attack_pattern(tech_id, name, [], author, markings), tech_id


def _build_attack_pattern(
    tech_id: str,
    name: str,
    tactics: list[str],
    author: stix2.Identity,
    markings: Optional[list[str]],
) -> stix2.AttackPattern:
    kill_chain_phases = [
        stix2.KillChainPhase(kill_chain_name=KILL_CHAIN, phase_name=_phase_slug(t))
        for t in tactics
        if t
    ]
    return stix2.AttackPattern(
        id=PyCtiAttackPattern.generate_id(name=name, x_mitre_id=tech_id),
        name=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
        kill_chain_phases=kill_chain_phases or None,
        external_references=[
            stix2.ExternalReference(
                source_name="mitre-attack",
                url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                external_id=tech_id,
            )
        ],
        allow_custom=True,
        custom_properties={"x_mitre_id": tech_id},
    )


def _phase_slug(tactic: str) -> str:
    slug = tactic.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
    return slug or "unknown"


def _build_intrusion_set(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.IntrusionSet:
    return stix2.IntrusionSet(
        id=PyCtiIntrusionSet.generate_id(name=name),
        name=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_campaign(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Campaign:
    return stix2.Campaign(
        id=PyCtiCampaign.generate_id(name=name),
        name=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_malware(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Malware:
    return stix2.Malware(
        id=PyCtiMalware.generate_id(name=name),
        name=name,
        is_family=True,
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_vulnerability(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Vulnerability:
    return stix2.Vulnerability(
        id=PyCtiVulnerability.generate_id(name=name),
        name=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_tool(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Tool:
    return stix2.Tool(
        id=PyCtiTool.generate_id(name=name),
        name=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_sector(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Identity:
    return stix2.Identity(
        id=PyCtiIdentity.generate_id(name, "class"),
        name=name,
        identity_class="class",
        created_by_ref=author.id,
        object_marking_refs=markings,
    )


def _build_country(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Location:
    return stix2.Location(
        id=PyCtiLocation.generate_id(name=name, x_opencti_location_type="Country"),
        name=name,
        country=name,
        created_by_ref=author.id,
        object_marking_refs=markings,
        allow_custom=True,
        custom_properties={"x_opencti_location_type": "Country"},
    )


def _build_region(
    name: str, author: stix2.Identity, markings: Optional[list[str]]
) -> stix2.Location:
    return stix2.Location(
        id=PyCtiLocation.generate_id(name=name, x_opencti_location_type="Region"),
        name=name,
        # STIX 2.1 Location requires region/country/lat+long; OpenCTI uses
        # x_opencti_location_type as the real discriminator. We mirror the name
        # into `region` to satisfy validation; OpenCTI ignores it on import.
        region=_region_vocab(name),
        created_by_ref=author.id,
        object_marking_refs=markings,
        allow_custom=True,
        custom_properties={"x_opencti_location_type": "Region"},
    )


def _region_vocab(name: str) -> str:
    """Best-effort map of a Hunter region name to the STIX 2.1 `region-ov`
    open vocabulary. Falls back to a slugified name (open vocab allows it)."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "unknown"


def _build_relationships(
    indicator: stix2.Indicator,
    related: list[Any],
    author: stix2.Identity,
    *,
    markings: Optional[list[str]],
) -> list[stix2.Relationship]:
    relationships: list[stix2.Relationship] = []
    for target in related:
        relationships.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates", indicator.id, target.id
                ),
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=target.id,
                created_by_ref=author.id,
                object_marking_refs=markings,
                allow_custom=True,
            )
        )

    # Intrusion-Set --uses--> Attack-Pattern for richer graph.
    intrusion_sets = [o for o in related if o.type == "intrusion-set"]
    attack_patterns = [o for o in related if o.type == "attack-pattern"]
    for actor in intrusion_sets:
        for technique in attack_patterns:
            relationships.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id("uses", actor.id, technique.id),
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=technique.id,
                    created_by_ref=author.id,
                    object_marking_refs=markings,
                    allow_custom=True,
                )
            )
    return relationships


def _cli() -> None:  # pragma: no cover
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Render a Hunter response into a STIX bundle."
    )
    parser.add_argument(
        "--fixture", required=True, help="Path to a Hunter response.json"
    )
    parser.add_argument("--out", default="-", help="Output path (default stdout)")
    args = parser.parse_args()

    with open(args.fixture, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    author = build_author()
    objects: list[Any] = [author]
    for hunt in payload.get("results", []):
        objects.extend(build_bundle(hunt, author))
    bundle = stix2.Bundle(objects=objects, allow_custom=True)

    serialized = bundle.serialize(indent=2)
    if args.out == "-":
        sys.stdout.write(serialized)
        sys.stdout.write("\n")
    else:
        with open(args.out, "w", encoding="utf-8") as out:
            out.write(serialized)


if __name__ == "__main__":  # pragma: no cover
    _cli()
