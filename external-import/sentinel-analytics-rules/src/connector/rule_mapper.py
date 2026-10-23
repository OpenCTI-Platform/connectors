"""Microsoft Sentinel alert rule -> ``DetectionRule``."""

import json
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
# ``pattern_type`` of a rule whose detection logic is not its query alone.
RULE_PATTERN_TYPE = "sentinel-rule"
# Trigger of a rule alerting as soon as its query returns a result.
_DEFAULT_TRIGGER = ("GreaterThan", 0)


def rule_pattern(kind: str, properties: dict[str, Any]) -> tuple[str, str]:
    """Return the Indicator ``pattern`` and ``pattern_type`` of a rule.

    The logic of a Scheduled rule is not its query alone: the lookback
    (``queryPeriod``) decides which events the query sees, and the trigger
    (``triggerOperator`` and ``triggerThreshold``) is applied to its results.
    Such a rule is represented by the canonical JSON of its kind, query,
    lookback and trigger, under the ``sentinel-rule`` pattern type: its
    Indicator changes with any of them, and two rules sharing a query but not
    their lookback or trigger are two Indicators. The KQL query is the pattern
    of an NRT rule, and of a Scheduled rule without lookback or trigger.
    """
    query = str(properties["query"])
    if kind != "Scheduled":
        return query, "kql"
    period = properties.get("queryPeriod")
    period = str(period).strip() if period is not None else ""
    operator = properties.get("triggerOperator")
    threshold = properties.get("triggerThreshold")
    try:
        trigger = (operator or _DEFAULT_TRIGGER[0], int(threshold or 0))
    except (TypeError, ValueError):
        trigger = (operator or _DEFAULT_TRIGGER[0], threshold)
    if not period and trigger == _DEFAULT_TRIGGER:
        return query, "kql"
    pattern = json.dumps(
        {
            "kind": kind,
            "query": query,
            "queryPeriod": period or None,
            "triggerOperator": trigger[0],
            "triggerThreshold": trigger[1],
        },
        sort_keys=True,
        indent=2,
    )
    return pattern, RULE_PATTERN_TYPE


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
    pattern, pattern_type = rule_pattern(str(kind), properties)

    return DetectionRule(
        external_id=str(rule_name),
        name=properties.get("displayName") or str(rule_name),
        description=properties.get("description") or None,
        pattern=pattern,
        pattern_type=pattern_type,
        enabled=bool(properties.get("enabled")),
        created_at=parse_timestamp(system_data.get("createdAt")),
        modified_at=parse_timestamp(
            properties.get("lastModifiedUtc") or system_data.get("lastModifiedAt")
        ),
        level=normalize_level(properties.get("severity")),
        techniques=_techniques(properties),
    )
