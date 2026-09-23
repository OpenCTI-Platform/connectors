"""Map an OpenCTI entity (as delivered to an enrichment connector) to the
right Hunter API query parameters.

Hunter `/es/query` parameter reference:
    https://api.hunter.cyborgsecurity.io/docs

Most entity types resolve to a single Hunter query. Location-family entities
(Country / Region / generic Location) resolve to *two* queries — one against
`target_*` and one against `source_*` — because Hunter's content authors
populate the source-attribution side far more consistently than the
target-targeting side, and the API ANDs across params so a single call
can't union them.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

LOGGER = logging.getLogger(__name__)

_MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

Query = dict[str, list[str]]


def _names_from(entity: dict[str, Any]) -> list[str]:
    names: list[str] = []
    if entity.get("name"):
        names.append(entity["name"])
    for alias in entity.get("aliases") or entity.get("x_opencti_aliases") or []:
        if alias and alias not in names:
            names.append(alias)
    return names


def _attack_pattern_id(entity: dict[str, Any]) -> Optional[str]:
    # OpenCTI surfaces the MITRE ID in different places depending on version.
    # We also accept it inline in the `name` field — useful for ad-hoc invocations
    # (e.g. dry_run --entity-name T1027) and for OpenCTI deployments where the
    # technique id is stored as the entity name.
    candidates = [
        entity.get("x_mitre_id"),
        entity.get("x_opencti_external_id"),
        entity.get("external_id"),
        entity.get("name"),
    ]
    for ref in entity.get("external_references") or []:
        if ref.get("source_name", "").lower().startswith("mitre"):
            candidates.append(ref.get("external_id"))
    for value in candidates:
        if value and _MITRE_ID_RE.match(value):
            return value.upper()
    return None


def build_query(entity: dict[str, Any]) -> Optional[list[Query]]:
    """Return one or more Hunter API query kwarg-sets for the given entity.

    Returns:
        None if the entity type is unsupported or the lookup keys are missing.
        Otherwise a list of dicts — each dict is one separate API call; the
        caller unions results (by hunt UUID) across calls.
    """
    if not entity:
        return None

    entity_type = (
        entity.get("entity_type")
        or entity.get("type")
        or entity.get("x_opencti_type")
        or ""
    )
    entity_type = entity_type.lower().replace("_", "-")

    if entity_type in {
        "intrusion-set",
        "threat-actor",
        "threat-actor-group",
        "threat-actor-individual",
    }:
        names = _names_from(entity)
        return [{"actors": names}] if names else None

    if entity_type == "campaign":
        names = _names_from(entity)
        return [{"campaigns": names}] if names else None

    if entity_type == "attack-pattern":
        mid = _attack_pattern_id(entity)
        if mid:
            return [{"mitre_technique_ids": [mid]}]
        names = _names_from(entity)
        if names:
            return [{"mitre_technique_names": names}]
        return None

    if entity_type == "vulnerability":
        names = _names_from(entity)
        return [{"exploit_or_vulns": names}] if names else None

    if entity_type == "malware":
        names = _names_from(entity)
        return [{"threat_names": names}] if names else None

    if entity_type == "tool":
        names = _names_from(entity)
        return [{"tools": names}] if names else None

    if entity_type == "sector":
        names = _names_from(entity)
        return [{"target_industries": names}] if names else None

    if entity_type in {"country", "region", "location"}:
        names = _names_from(entity)
        if not names:
            return None
        kind = _location_kind(entity_type, entity)
        if kind == "country":
            return [{"target_countries": names}, {"source_countries": names}]
        if kind == "region":
            return [{"target_regions": names}, {"source_regions": names}]
        return None

    LOGGER.info("Entity type %r is not in scope for Hunter enrichment", entity_type)
    return None


def _location_kind(entity_type: str, entity: dict[str, Any]) -> Optional[str]:
    """Resolve a Location-family entity to 'country', 'region', or None."""
    if entity_type == "country":
        return "country"
    if entity_type == "region":
        return "region"
    sub_type = (
        entity.get("x_opencti_location_type") or entity.get("location_type") or ""
    ).lower()
    if sub_type == "country":
        return "country"
    if sub_type == "region":
        return "region"
    # City / Administrative-Area / Position have no Hunter equivalent.
    LOGGER.info(
        "Location sub-type %r unsupported (Hunter has no city/area filter)",
        sub_type or "unknown",
    )
    return None
