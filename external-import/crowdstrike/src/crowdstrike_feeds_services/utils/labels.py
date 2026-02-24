# -*- coding: utf-8 -*-
"""CrowdStrike label parsing utilities.

This module is imported by crowdstrike_feeds_services.utils.__init__.

Goal:
- Normalize label values coming from CrowdStrike (strings + raw label objects)
- Provide convenience helpers for extracting label names and parsing into buckets

Common input shapes:
- "DataObfuscation"
- "Data Obfuscation"
- {"type": "attack_pattern", "value": "DataObfuscation"}
- {"name": "DataObfuscation"}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping

_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z])(?=[A-Z])")


def _dedupe_values(values: List[str], case_sensitive: bool = False) -> List[str]:
    """De-dupe lists while preserving order"""
    seen = set()
    deduped: List[str] = []
    for value in values:
        key = value if case_sensitive else value.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(value)
    return deduped


def _normalize_label_value(value: str) -> str:
    """Normalize a label value into a more human-friendly, consistent representation."""
    if value is None:
        return ""

    value = str(value).strip()
    if not value:
        return ""

    # If it's camelCase / PascalCase like "DataObfuscation", split into "Data Obfuscation".
    if " " not in value and _CAMEL_SPLIT_RE.search(value):
        value = _CAMEL_SPLIT_RE.sub(" ", value)

    # Collapse repeated whitespace
    value = " ".join(value.split())
    return value


def extract_label_names(labels: Iterable[str | dict]) -> List[str]:
    """Extract label names from mixed raw inputs.

    Accepts:
    - list[str]: where each string is a label name
    - list[dict]: where each dict may have 'value', 'name', 'label', 'slug'
    """
    names: List[str] = []
    for lab in labels:
        value = None

        if isinstance(lab, str):
            value = _normalize_label_value(lab)
        elif isinstance(lab, Mapping):
            value = (
                lab.get("value")
                or lab.get("name")
                or lab.get("label")
                or lab.get("slug")
                or ""
            )
            value = _normalize_label_value(str(value))

        if value:
            names.append(value)

    return _dedupe_values(names, case_sensitive=True)


@dataclass(frozen=True)
class ParsedLabels:
    """Parsed CrowdStrike labels bucketed into common categories."""

    attack_patterns: List[str]
    malware_families: List[str]
    actor_names: List[str]
    threat_types: List[str]
    raw: List[str]


def parse_crowdstrike_labels(raw_labels: Iterable[str | dict]) -> ParsedLabels:
    """Parse CrowdStrike labels from raw inputs (strings or dicts).

    This is a tolerant parser. If it can't confidently bucket a label, it will
    still appear in `raw`.
    """
    # Bucket heuristics:
    # If you have a strict schema in your payloads (e.g., dict['type']), we use it.
    attack_patterns: List[str] = []
    malware_families: List[str] = []
    actor_names: List[str] = []
    threat_types: List[str] = []

    # First pass: typed dicts
    for raw_label in raw_labels:
        if not isinstance(raw_label, Mapping):
            continue

        label_type = (
            (raw_label.get("type") or raw_label.get("category") or "").lower().strip()
        )
        value = (
            raw_label.get("value")
            or raw_label.get("name")
            or raw_label.get("label")
            or raw_label.get("slug")
            or ""
        )
        value = _normalize_label_value(str(value))
        if not value:
            continue

        if label_type in (
            "attack_pattern",
            "attack-pattern",
            "mitre",
            "tactic",
            "technique",
        ):
            attack_patterns.append(value)
        elif label_type in ("malware", "malware_family", "family"):
            malware_families.append(value)
        elif label_type in ("actor", "threat_actor", "intrusion_set", "intrusion-set"):
            actor_names.append(value)
        elif label_type in ("threat_type", "threat-type", "threat"):
            threat_types.append(value)

    # Second pass: parse common CrowdStrike string label conventions
    # Examples:
    # - "mitre attck/command and control/data obfuscation"
    # - "malware/mofksys"
    # - "actor/saltyspider"
    # - "threat type/botnet"
    label_names = extract_label_names(raw_labels)

    for label_name in label_names:
        low = label_name.lower().strip()
        value = None

        # MITRE ATT&CK labels (tactic / technique)
        mitre_prefixes = (
            "mitre attck/",
            "mitre att&ck/",
            "mitre attack/",
        )
        mitre_prefix = next((p for p in mitre_prefixes if low.startswith(p)), None)
        if mitre_prefix:
            remainder = label_name[len(mitre_prefix) :].strip("/").strip()
            if remainder:
                # CrowdStrike strings commonly look like: "<tactic>/<technique>".
                # OpenCTI AttackPattern names should be the MITRE technique name (or the technique ID when present).
                parts = [p.strip() for p in remainder.split("/") if p.strip()]
                # last segment is the technique name in the common case
                technique_part = parts[-1]

                # If the technique part begins with an ID like "T1059" or "T1059.001", keep only that ID.
                match = re.match(
                    r"^(T\d{4}(?:\.\d{3})?)\b", technique_part, flags=re.IGNORECASE
                )
                if match:
                    value = match.group(1).upper()
                else:
                    value = _normalize_label_value(technique_part)
                if value:
                    attack_patterns.append(value)

        # Malware family labels
        if low.startswith("malware/"):
            value = label_name.split("/", 1)[1].strip()
            if value:
                malware_families.append(value)

        # Actor labels
        if low.startswith("actor/"):
            value = label_name.split("/", 1)[1].strip()
            if value:
                actor_names.append(value)

        # Threat type labels
        if low.startswith(("threat type/", "threat-type/")):
            value = label_name.split("/", 1)[1].strip()
            if value:
                threat_types.append(value)

    attack_patterns = _dedupe_values(attack_patterns)
    malware_families = _dedupe_values(malware_families)
    actor_names = _dedupe_values(actor_names)
    threat_types = _dedupe_values(threat_types)

    # Remove labels that have been promoted into objects/fields.
    # (We keep labels like confidence/kill-chain labels that are not promoted.)
    promoted_prefixes = (
        "mitre attck/",
        "mitre att&ck/",
        "mitre attack/",
        "malware/",
        "actor/",
        "threat type/",
        "threat-type/",
    )

    filtered_raw: List[str] = []
    for label_name in label_names:
        low = label_name.lower().strip()
        if low.startswith(promoted_prefixes):
            continue
        filtered_raw.append(label_name)

    return ParsedLabels(
        attack_patterns=attack_patterns,
        malware_families=malware_families,
        actor_names=actor_names,
        threat_types=threat_types,
        raw=filtered_raw,
    )
