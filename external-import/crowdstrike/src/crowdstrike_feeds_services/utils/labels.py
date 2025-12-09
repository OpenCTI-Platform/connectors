# -*- coding: utf-8 -*-
"""CrowdStrike label parsing utilities."""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ParsedLabels:
    """Structured representation of CrowdStrike labels."""

    raw_labels: List[str]

    actors: Set[str] = field(default_factory=set)
    malware_families: Set[str] = field(default_factory=set)
    kill_chains: Set[str] = field(default_factory=set)
    threat_types: Set[str] = field(default_factory=set)
    malicious_confidences: Set[str] = field(default_factory=set)

    mitre_tactics: Set[str] = field(default_factory=set)
    mitre_technique_names: Set[str] = field(default_factory=set)
    mitre_tactic_technique_pairs: Set[Tuple[str, str]] = field(default_factory=set)

    other: Dict[str, Set[str]] = field(default_factory=dict)


def extract_label_names(labels: Any) -> List[str]:
    """Normalize CrowdStrike labels into a list of label-name strings.

    Supports:
      - [{"name": "Actor/SALTYSPIDER", ...}, ...]
      - ["Actor/SALTYSPIDER", ...]
      - single string value
    """
    if not labels:
        return []

    # Case 1: list of dicts with "name"
    if isinstance(labels, list) and labels and isinstance(labels[0], dict):
        names: List[str] = []
        for item in labels:
            name = item.get("name")
            if name:
                names.append(str(name))
        return names

    # Case 2: list of strings / primitives
    if isinstance(labels, list):
        return [str(l) for l in labels if l]

    # Fallback: single value
    return [str(labels)]


def parse_crowdstrike_labels_from_raw(labels_raw: Any) -> ParsedLabels:
    """Entry point to parse the 'labels' field from a CrowdStrike resource."""
    label_strings = extract_label_names(labels_raw)
    return parse_crowdstrike_labels(label_strings)


def parse_crowdstrike_labels(labels: Iterable[str]) -> ParsedLabels:
    """Parse CrowdStrike-style labels into a structured representation.

    Example patterns:
      - 'Actor/SALTYSPIDER'
      - 'Malware/SalityV4'
      - 'KillChain/Installation'
      - 'ThreatType/Botnet'
      - 'MaliciousConfidence/High'
      - 'MitreATTCK/CommandAndControl/DataObfuscation'
    """
    parsed = ParsedLabels(raw_labels=list(labels))

    for raw in labels:
        if not raw:
            continue

        parts = [p for p in str(raw).split("/") if p]
        if not parts:
            continue

        ns = parts[0].lower()
        rest = parts[1:]

        # --- Actors ---
        if ns == "actor":
            if rest:
                parsed.actors.add(rest[-1])
            continue

        # --- Malware families ---
        if ns == "malware":
            if rest:
                parsed.malware_families.add(rest[-1])
            continue

        # --- Kill chain phases ---
        if ns == "killchain":
            if rest:
                parsed.kill_chains.add(rest[-1])
            continue

        # --- Threat types ---
        if ns == "threattype":
            if rest:
                parsed.threat_types.add(rest[-1])
            continue

        # --- Malicious confidence ---
        if ns == "maliciousconfidence":
            if rest:
                parsed.malicious_confidences.add(rest[-1])
            continue

        # --- MITRE ATT&CK (tactic / technique *name*) ---
        #
        # Pattern from your sample:
        #   MitreATTCK/<tactic>/<techniqueName>
        if ns == "mitreattck":
            if not rest:
                continue

            tactic = rest[0]
            parsed.mitre_tactics.add(tactic)

            if len(rest) >= 2:
                technique_name = rest[1]
                parsed.mitre_technique_names.add(technique_name)
                parsed.mitre_tactic_technique_pairs.add((tactic, technique_name))
            continue

        # --- Fallback / unknown namespaces ---
        if ns not in parsed.other:
            parsed.other[ns] = set()

        value = "/".join(rest) if rest else ns
        parsed.other[ns].add(value)

    logger.debug(
        "Parsed CrowdStrike labels into structured form: %s",
        {
            "raw_labels": parsed.raw_labels,
            "actors": parsed.actors,
            "malware_families": parsed.malware_families,
            "kill_chains": parsed.kill_chains,
            "threat_types": parsed.threat_types,
            "malicious_confidences": parsed.malicious_confidences,
            "mitre_tactics": parsed.mitre_tactics,
            "mitre_technique_names": parsed.mitre_technique_names,
        },
    )

    return parsed
