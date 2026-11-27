"""Markdown summary of a GTI assessment, for IOC descriptions."""

from collections.abc import Collection
from typing import Any

from connector.src.custom.mappers.description_details import (
    bullet_section,
    details_section,
    join_sections,
)
from connector.src.custom.mappers.gti_iocs.gti_links import gti_gui_url

# Boolean contributing factors, in display order. Fields missing on an IOC type are skipped.
CONTRIBUTING_FACTOR_LABELS = {
    "mandiant_analyst_malicious": "Determined malicious by a Mandiant analyst",
    "mandiant_analyst_benign": "Determined benign by a Mandiant analyst",
    "mandiant_association_actor": "Associated with a tracked threat actor",
    "mandiant_association_malware": "Associated with a tracked malware family",
    "mandiant_association_report": "Referenced in a GTI intelligence report",
    "associated_actor": "Associated with a community threat actor",
    "associated_malware_configuration": "Contains a known malware configuration",
    "malicious_sandbox_verdict": "Detected as malicious by sandbox analysis",
    "matched_malicious_yara": "Matches malicious YARA rules",
    "mandiant_domain_hijack": "Domain hijacked",
    "high_severity_related_files": "Related to high severity malicious files",
    "medium_severity_related_files": "Related to medium severity malicious files",
    "low_severity_related_files": "Related to low severity malicious files",
    "mandiant_osint": "Widespread in OSINT sources",
    "pervasive_indicator": "Pervasive indicator",
    "associated_reference": "Referenced in public sources",
    "legitimate_software": "Associated with legitimate software",
}


# Valued contributing factors, shown as "label: value".
CONTRIBUTING_FACTOR_VALUES = {
    "gti_confidence_score": "GTI confidence score",
    "mandiant_confidence_score": "Mandiant confidence score",
    "gavs_detections": "Google threat filtering detections",
    "safebrowsing_verdict": "Google Safe Browsing verdict",
}


def _humanize(value: str | None, prefix: str) -> str | None:
    """Turn 'VERDICT_MALICIOUS' into 'Malicious'."""
    if not value:
        return None
    return value.removeprefix(prefix).replace("_", " ").capitalize()


def _contributing_factors(factors: Any) -> list[str]:
    if factors is None:
        return []
    lines = [
        label
        for field, label in CONTRIBUTING_FACTOR_LABELS.items()
        if getattr(factors, field, None) is True
    ]
    for field, label in CONTRIBUTING_FACTOR_VALUES.items():
        value = getattr(factors, field, None)
        if value:
            lines.append(f"{label}: {value}")
    return lines


def _card_links(card: Any) -> str | None:
    """Return the related links of a card, as Markdown links to GTI when possible."""
    links = []
    for link in getattr(card, "related_links", None) or []:
        target = getattr(link, "url", None)
        title = getattr(link, "title", None) or getattr(target, "id", None)
        if not title:
            continue
        url = gti_gui_url(
            getattr(target, "object_type", None), getattr(target, "id", None)
        )
        links.append(f"[{title}]({url})" if url else title)
    return ", ".join(links) or None


def _card_line(card: Any) -> str | None:
    """Return 'title: sub title (influence influence). Related: links'."""
    title = getattr(card, "title", None)
    if not title:
        return None
    line = str(title)
    if sub_title := getattr(card, "sub_title", None):
        line += f": {sub_title}"
    if influence := getattr(card, "influence", None):
        line += f" ({influence} influence)"
    if links := _card_links(card):
        line += f". Related: {links}"
    return line


def _description_cards(cards: Any) -> list[str | None]:
    """Return one bullet section per card category, in GTI order."""
    return [
        bullet_section(
            _humanize(category, "") or category,
            filter(None, (_card_line(card) for card in category_cards or [])),
        )
        for category, category_cards in (cards or {}).items()
    ]


def build_assessment_description(gti_assessment: Any) -> str | None:
    """Build a Markdown summary of the verdict, severity, score and their reasons.

    Order: GTI summary, explanation cards, assessment details, contributing factors.

    Args:
        gti_assessment: GTI assessment of a collection IOC or an IOC delta entry.

    Returns:
        The description, or None when the assessment holds nothing to show.

    """
    if gti_assessment is None:
        return None

    verdict = getattr(gti_assessment, "verdict", None)
    severity = getattr(gti_assessment, "severity", None)
    threat_score = getattr(gti_assessment, "threat_score", None)
    return join_sections(
        getattr(gti_assessment, "description", None),
        *_description_cards(getattr(gti_assessment, "gti_description_cards", None)),
        details_section(
            "GTI assessment",
            {
                "Verdict": _humanize(getattr(verdict, "value", None), "VERDICT_"),
                "Severity": _humanize(getattr(severity, "value", None), "SEVERITY_"),
                "Threat score": getattr(threat_score, "value", None),
            },
        ),
        bullet_section(
            "Contributing factors",
            _contributing_factors(
                getattr(gti_assessment, "contributing_factors", None)
            ),
        ),
    )


def network_details_section(
    attributes: Any, linked_fields: Collection[str] = ()
) -> str | None:
    """Return the network details of an IP IOC: country, ASN, range, registry.

    Fields missing on an IOC type are skipped, so other types give None.

    Args:
        attributes: GTI IOC attributes.
        linked_fields: Fields imported as linked objects, left out: 'country' (Country
            location), 'asn' (autonomous system, with its owner and registry).

    """
    asn = getattr(attributes, "asn", None)
    as_owner = getattr(attributes, "as_owner", None)
    autonomous_system = None
    if asn is not None and "asn" not in linked_fields:
        autonomous_system = f"AS{asn} ({as_owner})" if as_owner else f"AS{asn}"
    country = (
        None if "country" in linked_fields else getattr(attributes, "country", None)
    )
    registry = None
    if "asn" not in linked_fields:
        registry = getattr(attributes, "regional_internet_registry", None)
    return details_section(
        "GTI network details",
        {
            "Country": country,
            "Continent": getattr(attributes, "continent", None),
            "Autonomous system": autonomous_system,
            "Network": getattr(attributes, "network", None),
            "Regional internet registry": registry,
        },
    )


def build_ioc_description(
    attributes: Any, linked_fields: Collection[str] = ()
) -> str | None:
    """Return the GTI assessment description, then the network details of IPs.

    Args:
        attributes: GTI IOC attributes.
        linked_fields: See `network_details_section`.

    """
    if attributes is None:
        return None
    return join_sections(
        build_assessment_description(getattr(attributes, "gti_assessment", None)),
        threat_severity_section(attributes),
        network_details_section(attributes, linked_fields),
    )


def threat_category(attributes: Any) -> str | None:
    """Return the GTI threat category of a file IOC, e.g. 'trojan', or None."""
    severity = getattr(attributes, "threat_severity", None)
    data = getattr(severity, "threat_severity_data", None)
    return getattr(data, "popular_threat_category", None) or None


def threat_severity_section(attributes: Any) -> str | None:
    """Return the GTI threat severity of a file IOC: level and its explanation."""
    severity = getattr(attributes, "threat_severity", None)
    if severity is None:
        return None
    return details_section(
        "GTI threat severity",
        {
            "Level": _humanize(
                getattr(severity, "threat_severity_level", None), "SEVERITY_"
            ),
            "Explanation": getattr(severity, "level_description", None),
            "Threat category": threat_category(attributes),
        },
    )


def ioc_tag_labels(
    tags: list[str] | None, category: str | None = None
) -> list[str] | None:
    """Return the GTI tags, then the threat category, as labels, deduplicated, or None."""
    labels = [*(tags or []), category]
    return list(dict.fromkeys(label for label in labels if label)) or None


def observable_description_properties(description: str | None) -> dict[str, Any]:
    """Return the custom properties carrying an observable description."""
    return {"x_opencti_description": description} if description else {}
