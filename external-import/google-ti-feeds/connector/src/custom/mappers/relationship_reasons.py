"""Relationship descriptions stating why the connector created a relationship.

"Stated by GTI" marks a GTI association, "Inferred by the connector" a link GTI
does not state. Written only with GTI_RELATIONSHIP_DESCRIPTIONS: by default the
connector leaves relationship descriptions empty, so it never overwrites a
description written by an analyst or another source (#5775).
"""

from typing import Any

from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    CONTRIBUTING_FACTOR_LABELS,
)
from pydantic import BaseModel

# Set by the converters from GTI_RELATIONSHIP_DESCRIPTIONS.
_SETTINGS = {"enabled": False}


def set_relationship_descriptions(enabled: bool) -> None:
    """Enable or disable the relationship descriptions of this module."""
    _SETTINGS["enabled"] = enabled


def optional_reason(reason: str) -> str | None:
    """Return the reason when relationship descriptions are enabled, else None."""
    return reason if _SETTINGS["enabled"] else None


# STIX type -> label used in descriptions. Other types: type with spaces.
STIX_TYPE_LABELS = {
    "attack-pattern": "attack pattern",
    "autonomous-system": "autonomous system",
    "domain-name": "domain",
    "intrusion-set": "intrusion set",
    "ipv4-addr": "IP address",
    "ipv6-addr": "IP address",
    "url": "URL",
}


def type_label(obj: Any) -> str:
    """Return the label of the STIX type of an object, e.g. 'intrusion set'."""
    stix_type = str(getattr(obj, "type", "object"))
    if stix_type == "location" and (
        location_type := _get(obj, "x_opencti_location_type")
    ):
        return str(location_type).lower()
    if stix_type == "identity" and _get(obj, "identity_class") == "class":
        return "sector"
    return STIX_TYPE_LABELS.get(stix_type, stix_type.replace("-", " "))


def _get(obj: Any, field: str) -> Any:
    """Return a field of a STIX object, custom properties included."""
    value = getattr(obj, field, None)
    if value is None and hasattr(obj, "get"):
        value = obj.get(field)
    return value


def display_name(obj: Any) -> str:
    """Return the name shown for an object: name, value, SHA-256, AS number, or ID."""
    for field in ("name", "value"):
        value = getattr(obj, field, None)
        if value:
            return str(value)
    hashes = getattr(obj, "hashes", None) or {}
    if sha256 := hashes.get("SHA-256"):
        return str(sha256)
    if (number := getattr(obj, "number", None)) is not None:
        return f"AS{number}"
    return str(getattr(obj, "id", "unknown"))


def describe(obj: Any) -> str:
    """Return "the <type> '<name>'"."""
    return f"the {type_label(obj)} '{display_name(obj)}'"


def with_description(relationship: Any, description: str) -> Any:
    """Return the relationship model with `description` when it has none and enabled.

    Objects other than Pydantic relationship models are returned unchanged.
    """
    if not _SETTINGS["enabled"] or (
        not isinstance(relationship, BaseModel)
        or "description" not in type(relationship).model_fields
    ):
        return relationship
    if getattr(relationship, "description", None):
        return relationship
    return relationship.model_copy(update={"description": description})


def gti_association_reason(context_entity: Any, entity: Any) -> str:
    """Reason for a link from a GTI collection to an entity it lists."""
    return (
        f"Stated by GTI: Google Threat Intelligence lists {describe(entity)} "
        f"among the related objects of {describe(context_entity)}."
    )


def report_text_link_reason(report: Any, threat: Any) -> str:
    """Reason for a link from a report to a threat it links to only in its text.

    Always written, with or without GTI_RELATIONSHIP_DESCRIPTIONS: it is what
    tells these links from the report contents GTI lists.
    """
    return (
        f"Inferred by the connector, not stated by GTI: {describe(report)} links to "
        f"{describe(threat)} in its text, but GTI does not list it among the related "
        "objects of the report."
    )


def ioc_delta_association_reason(target: Any) -> str:
    """Reason for a link from an IOC deltas feed indicator to an entity of its entry."""
    return (
        f"Stated by GTI: the IOC deltas feed lists {describe(target)} among the "
        "relationships of this IOC."
    )


def ip_autonomous_system_reason(asn: int, as_owner: str | None) -> str:
    """Reason for the link from an IP to its autonomous system."""
    owner = f" ({as_owner})" if as_owner else ""
    return (
        f"Stated by GTI: GTI lists AS{asn}{owner} as the autonomous system of this IP."
    )


def ip_country_reason(country_name: str, country_code: str) -> str:
    """Reason for the link from an IP to its country."""
    return (
        f"Stated by GTI: GTI geolocates this IP in {country_name} "
        f"(country code {country_code})."
    )


# (relationship type, target STIX type) -> GTI list the target comes from.
TARGETING_LISTS = {
    ("targets", "location"): "targeted regions",
    ("targets", "identity"): "targeted industries",
    ("originates-from", "location"): "source regions",
}


def targeting_reason(
    source: Any, relationship_type: str, target: Any, timing: Any
) -> str | None:
    """Description of a targets or originates-from link: the GTI confidence and note.

    The GTI confidence and note are GTI content, written even when relationship
    descriptions are disabled. With them enabled, the GTI list the target comes
    from is stated first.

    Args:
        source: The intrusion set, malware, tool or campaign.
        relationship_type: 'targets' or 'originates-from'.
        target: The location or sector.
        timing: The `LocationWithTiming` or `IdentityWithTiming` of the target.

    Returns:
        The description, or None when disabled and GTI gives no confidence or note.

    """
    confidence = getattr(timing, "confidence", None)
    note = (getattr(timing, "note", None) or "").strip()
    supplier = getattr(timing, "source", None)
    if not _SETTINGS["enabled"]:
        gti_content = [
            f"GTI confidence: {confidence}." if confidence else "",
            f"Source: {supplier}." if supplier else "",
            note,
        ]
        return " ".join(part for part in gti_content if part) or None

    gti_list = TARGETING_LISTS.get(
        (relationship_type, str(getattr(target, "type", ""))), "related objects"
    )
    reason = (
        f"Stated by GTI: GTI lists {describe(target)} among the {gti_list} "
        f"of {describe(source)}"
    )
    if confidence:
        reason += f", with confidence '{confidence}'"
    if supplier:
        reason += f", source '{supplier}'"
    reason += "."
    if note:
        reason += f" GTI note: {note}"
    return reason


# Threat STIX type -> contributing factors of an IOC supporting a link to it.
EVIDENCE_FACTORS = {
    "intrusion-set": ("mandiant_association_actor", "associated_actor"),
    "malware": ("mandiant_association_malware", "associated_malware_configuration"),
    "report": ("mandiant_association_report",),
}


def gti_collection_id(obj: Any) -> str | None:
    """Return the GTI collection ID of an object, from its GTI external reference."""
    for reference in _get(obj, "external_references") or []:
        url = _get(reference, "url") or ""
        if "/gui/collection/" in url:
            return str(url.rsplit("/", 1)[-1]) or None
    return None


def _card_points_to(card: Any, threat_name: str | None, threat_id: str | None) -> bool:
    """Return whether a GTI explanation card links to the threat, by GTI ID or name."""
    name = (threat_name or "").casefold()
    for link in getattr(card, "related_links", None) or []:
        target = getattr(link, "url", None)
        if threat_id and getattr(target, "id", None) == threat_id:
            return True
        if name and (getattr(link, "title", None) or "").casefold() == name:
            return True
    return False


def _sandbox_evidence(sandbox_verdicts: Any, malware_name: str | None) -> list[str]:
    """Return the sandbox verdicts of a file naming the malware family."""
    name = (malware_name or "").casefold()
    if not name:
        return []
    parts = []
    for sandbox, verdict in (sandbox_verdicts or {}).items():
        names = getattr(verdict, "malware_names", None) or []
        if name not in (detected.casefold() for detected in names):
            continue
        details = [
            getattr(verdict, "category", None) or "",
            (
                f"confidence {verdict.confidence}"
                if getattr(verdict, "confidence", None) is not None
                else ""
            ),
        ]
        detail_text = ", ".join(detail for detail in details if detail)
        parts.append(
            f"sandbox '{getattr(verdict, 'sandbox_name', None) or sandbox}' detects "
            f"{', '.join(names)}" + (f" ({detail_text})" if detail_text else "")
        )
    return parts


def ioc_threat_evidence(
    gti_assessment: Any,
    threat_type: str | None,
    threat_name: str | None,
    threat_id: str | None,
    sandbox_verdicts: Any = None,
) -> str | None:
    """Return the GTI evidence of an IOC supporting its link to a threat.

    Explanation cards linking to the threat, the contributing factors supporting a
    link to that type of threat, then for malware the file sandbox verdicts naming it.

    Args:
        gti_assessment: GTI assessment of the IOC.
        threat_type: STIX type of the threat, e.g. 'intrusion-set'.
        threat_name: Name of the threat, matched to the card link titles.
        threat_id: GTI collection ID of the threat, matched to the card link IDs.
        sandbox_verdicts: Sandbox verdicts of a file IOC, by sandbox.

    Returns:
        "Evidence: ...", or None when GTI gives none.

    """
    parts = []
    for category_cards in (
        getattr(gti_assessment, "gti_description_cards", None) or {}
    ).values():
        for card in category_cards or []:
            title = getattr(card, "title", None)
            if title and _card_points_to(card, threat_name, threat_id):
                influence = getattr(card, "influence", None)
                parts.append(
                    f"GTI explanation card '{title}'"
                    + (f" ({influence} influence)" if influence else "")
                )
    factors = getattr(gti_assessment, "contributing_factors", None)
    for field in EVIDENCE_FACTORS.get(threat_type or "", ()):
        if getattr(factors, field, None) is True:
            parts.append(f"contributing factor '{CONTRIBUTING_FACTOR_LABELS[field]}'")
    if threat_type == "malware":
        parts.extend(_sandbox_evidence(sandbox_verdicts, threat_name))
    return f"Evidence: {'; '.join(parts)}." if parts else None


def co_occurrence_reason(
    source: Any, target: Any, container: Any | None, source_ioc: Any = None
) -> str:
    """Reason for a link between two entities of the same report or campaign.

    Args:
        source: Source of the relationship.
        target: Target of the relationship.
        container: The report or campaign referencing both.
        source_ioc: GTI data of the source when it is an IOC: its GTI evidence
            supporting a link to the target is appended.

    """
    where = describe(container) if container is not None else "a GTI report or campaign"
    reason = (
        f"Inferred by the connector, not stated by GTI: {describe(source)} and "
        f"{describe(target)} are both referenced by {where}."
    )
    attributes = getattr(source_ioc, "attributes", None)
    if attributes is None:
        return reason
    evidence = ioc_threat_evidence(
        getattr(attributes, "gti_assessment", None),
        getattr(target, "type", None),
        getattr(target, "name", None),
        gti_collection_id(target),
        getattr(attributes, "sandbox_verdicts", None),
    )
    return f"{reason} {evidence}" if evidence else reason
