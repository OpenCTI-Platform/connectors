"""Microsoft Sentinel alert rule -> ``DetectionRule``."""

from typing import Any

from connector.attack_patterns import normalize_technique_id
from connector.detection_rule import (
    DetectionRule,
    RuleSkippedError,
    normalize_level,
    parse_timestamp,
)

# Rule kinds carrying a KQL query. Fusion, ML Behavior Analytics, Threat
# Intelligence and Microsoft Security Incident Creation rules are built-in
# correlations without detection logic to represent as a pattern.
QUERY_RULE_KINDS = ("Scheduled", "NRT")


def _techniques(properties: dict[str, Any]) -> dict[str, str | None]:
    techniques: dict[str, str | None] = {}
    for value in [
        *(properties.get("techniques") or []),
        *(properties.get("subTechniques") or []),
    ]:
        mitre_id = normalize_technique_id(value)
        if mitre_id:
            techniques[mitre_id] = None
    return techniques


def map_rule(raw: dict[str, Any]) -> DetectionRule:
    """Map an alert rule of the ``alertRules`` API.

    Only Scheduled and NRT rules carry a KQL query; other kinds are left out.
    """
    kind = raw.get("kind")
    if kind not in QUERY_RULE_KINDS:
        raise RuleSkippedError(f"kind_{kind or 'unknown'}")
    properties = raw.get("properties") or {}
    query = properties.get("query")
    if not query or not str(query).strip():
        raise RuleSkippedError("no_query")
    rule_name = raw.get("name")
    if not rule_name:
        raise RuleSkippedError("no_rule_id")
    system_data = raw.get("systemData") or {}

    return DetectionRule(
        external_id=str(rule_name),
        name=properties.get("displayName") or str(rule_name),
        description=properties.get("description") or None,
        pattern=str(query),
        pattern_type="kql",
        enabled=bool(properties.get("enabled")),
        created_at=parse_timestamp(system_data.get("createdAt")),
        modified_at=parse_timestamp(
            properties.get("lastModifiedUtc") or system_data.get("lastModifiedAt")
        ),
        level=normalize_level(properties.get("severity")),
        techniques=_techniques(properties),
    )
