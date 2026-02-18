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
    - list[str]
    - list[dict] where dict may have 'value', 'name', 'label', 'slug'
    """
    names: List[str] = []
    for lab in labels:
        if lab is None:
            continue

        if isinstance(lab, str):
            val = _normalize_label_value(lab)
        elif isinstance(lab, Mapping):
            val = (
                lab.get("value")
                or lab.get("name")
                or lab.get("label")
                or lab.get("slug")
                or ""
            )
            val = _normalize_label_value(str(val))
        else:
            val = _normalize_label_value(str(lab))

        if val:
            names.append(val)

    # De-dupe preserving order
    seen = set()
    deduped: List[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    return deduped


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
    label_names = extract_label_names(raw_labels)

    # Bucket heuristics:
    # If you have a strict schema in your payloads (e.g., dict['type']), we use it.
    attack_patterns: List[str] = []
    malware_families: List[str] = []
    actor_names: List[str] = []
    threat_types: List[str] = []

    # First pass: typed dicts
    if raw_labels:
        for lab in raw_labels:
            if not isinstance(lab, Mapping):
                continue

            ltype = (lab.get("type") or lab.get("category") or "").lower().strip()
            val = (
                lab.get("value")
                or lab.get("name")
                or lab.get("label")
                or lab.get("slug")
                or ""
            )
            val = _normalize_label_value(str(val))
            if not val:
                continue

            if ltype in (
                "attack_pattern",
                "attack-pattern",
                "mitre",
                "tactic",
                "technique",
            ):
                attack_patterns.append(val)
            elif ltype in ("malware", "malware_family", "family"):
                malware_families.append(val)
            elif ltype in ("actor", "threat_actor", "intrusion_set", "intrusion-set"):
                actor_names.append(val)
            elif ltype in ("threat_type", "threat-type", "threat"):
                threat_types.append(val)

    # Second pass: parse common CrowdStrike string label conventions
    # Examples:
    # - "mitre attck/command and control/data obfuscation"
    # - "malware/mofksys"
    # - "actor/saltyspider"
    # - "threat type/botnet"

    for lbl in label_names:
        if not lbl:
            continue

        low = lbl.lower().strip()

        # MITRE ATT&CK labels (tactic / technique)
        mitre_prefixes = (
            "mitre attck/",
            "mitre att&ck/",
            "mitre attack/",
        )

        mitre_prefix = next((p for p in mitre_prefixes if low.startswith(p)), None)
        if mitre_prefix:
            remainder = lbl[len(mitre_prefix) :].strip("/").strip()
            if remainder:
                parts = [p.strip() for p in remainder.split("/") if p.strip()]

                # CrowdStrike strings commonly look like: "<tactic>/<technique>".
                # OpenCTI AttackPattern names should be the MITRE technique name (or the technique ID when present).
                technique_part = parts[
                    -1
                ]  # last segment is the technique name in the common case

                # If the technique part begins with an ID like "T1059" or "T1059.001", keep only that ID.
                m = re.match(
                    r"^(T\d{4}(?:\.\d{3})?)\b", technique_part, flags=re.IGNORECASE
                )
                if m:
                    attack_patterns.append(m.group(1).upper())
                else:
                    attack_patterns.append(_normalize_label_value(technique_part))
            continue

        # Malware family labels
        if low.startswith("malware/"):
            val = lbl.split("/", 1)[1].strip()
            if val:
                malware_families.append(val)
            continue

        # Actor labels
        if low.startswith("actor/"):
            val = lbl.split("/", 1)[1].strip()
            if val:
                actor_names.append(val)
            continue

        # Threat type labels
        if low.startswith("threat type/") or low.startswith("threat-type/"):
            val = lbl.split("/", 1)[1].strip()
            if val:
                threat_types.append(val)
            continue

    # De-dupe typed lists while preserving order
    def _dedupe(xs: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in xs:
            key = x.lower()
            if key not in seen:
                seen.add(key)
                out.append(x)
        return out

    attack_patterns = _dedupe(attack_patterns)
    malware_families = _dedupe(malware_families)
    actor_names = _dedupe(actor_names)
    threat_types = _dedupe(threat_types)

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
    for lbl in label_names:
        if not lbl:
            continue
        low = lbl.lower().strip()
        if any(low.startswith(p) for p in promoted_prefixes):
            continue
        filtered_raw.append(lbl)

    return ParsedLabels(
        attack_patterns=attack_patterns,
        malware_families=malware_families,
        actor_names=actor_names,
        threat_types=threat_types,
        raw=filtered_raw,
    )
