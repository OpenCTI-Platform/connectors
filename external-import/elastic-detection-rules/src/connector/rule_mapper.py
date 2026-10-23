"""Elastic Security detection rule -> ``DetectionRule``."""

import json
from collections.abc import Callable
from typing import Any

from connector.attack_patterns import normalize_technique_id
from connector.detection_rule import (
    DetectionRule,
    RuleSkippedError,
    normalize_level,
    parse_timestamp,
)

# Rule ``language`` -> ``pattern_type`` of the rule Indicator.
PATTERN_TYPES = {"kuery": "kuery", "lucene": "lucene", "eql": "eql", "esql": "esql"}
# ``pattern_type`` of a rule whose detection logic is not its query alone.
RULE_PATTERN_TYPE = "elastic-rule"
# Language of the rule types that do not state one.
_DEFAULT_LANGUAGES = {"eql": "eql", "esql": "esql"}
# Fields of the rule types that detect on more than the events their query matches.
_CONDITION_FIELDS = {
    "threshold": ("threshold",),
    "new_terms": ("new_terms_fields", "history_window_start"),
    "threat_match": (
        "threat_query",
        "threat_language",
        "threat_index",
        "threat_mapping",
        "threat_filters",
        "threat_indicator_path",
    ),
}
# ``OS: <name>`` rule tags -> MITRE ATT&CK platform.
_OS_PLATFORMS = {"windows": "windows", "linux": "linux", "macos": "macos"}
_ATTACK_FRAMEWORK = "MITRE ATT&CK"


def _techniques(threats: Any) -> dict[str, str | None]:
    techniques: dict[str, str | None] = {}
    for threat in threats or []:
        if not isinstance(threat, dict) or threat.get("framework") != _ATTACK_FRAMEWORK:
            continue
        for technique in threat.get("technique") or []:
            mitre_id = normalize_technique_id(technique.get("id"))
            if mitre_id:
                techniques[mitre_id] = technique.get("name") or None
            for sub_technique in technique.get("subtechnique") or []:
                sub_id = normalize_technique_id(sub_technique.get("id"))
                if sub_id:
                    techniques[sub_id] = sub_technique.get("name") or None
    return techniques


def _platforms(tags: Any) -> list[str]:
    platforms: list[str] = []
    for tag in tags or []:
        label, _, value = str(tag).partition(":")
        if label.strip().lower() != "os":
            continue
        platform = _OS_PLATFORMS.get(value.strip().lower())
        if platform and platform not in platforms:
            platforms.append(platform)
    return platforms


def _active_filters(filters: Any) -> list[dict[str, Any]]:
    """Return the query filters that apply, without their display metadata."""
    active = []
    for query_filter in filters or []:
        if not isinstance(query_filter, dict):
            continue
        meta = query_filter.get("meta") or {}
        if meta.get("disabled"):
            continue
        condition = {
            key: value
            for key, value in query_filter.items()
            if key not in ("meta", "$state")
        }
        condition["negate"] = bool(meta.get("negate"))
        active.append(condition)
    return active


def rule_pattern(raw: dict[str, Any], language: str) -> tuple[str, str]:
    """Return the Indicator ``pattern`` and ``pattern_type`` of a rule.

    The query is the pattern when it holds the whole detection logic. A rule
    with conditions outside its query (a threshold, new terms, an indicator
    match, or query filters) is represented by the canonical JSON of its
    type, language, query and conditions, under the ``elastic-rule`` pattern
    type: its Indicator changes whenever one of them does, and two rules
    sharing a query but not their conditions are two Indicators.
    """
    rule_type = raw.get("type")
    conditions: dict[str, Any] = {
        key: raw[key]
        for key in _CONDITION_FIELDS.get(str(rule_type), ())
        if raw.get(key) not in (None, "", [], {})
    }
    filters = _active_filters(raw.get("filters"))
    if filters:
        conditions["filters"] = filters
    if not conditions:
        return str(raw["query"]), PATTERN_TYPES[language]
    pattern = json.dumps(
        {"type": rule_type, "language": language, "query": raw["query"], **conditions},
        sort_keys=True,
        indent=2,
    )
    return pattern, RULE_PATTERN_TYPE


def map_rule(raw: dict[str, Any], rule_url: Callable[[str], str]) -> DetectionRule:
    """Map a rule of the Kibana ``_find`` API.

    Machine learning rules have no query and are left out, like rules whose
    query language has no rule ``pattern_type``.
    """
    rule_type = raw.get("type")
    if rule_type == "machine_learning":
        raise RuleSkippedError("machine_learning")
    query = raw.get("query")
    if not query or not str(query).strip():
        raise RuleSkippedError("no_query")
    language = raw.get("language") or _DEFAULT_LANGUAGES.get(rule_type, "kuery")
    if str(language).lower() not in PATTERN_TYPES:
        raise RuleSkippedError(f"language_{language}")
    pattern, pattern_type = rule_pattern(raw, str(language).lower())
    rule_id = raw.get("rule_id")
    if not rule_id:
        raise RuleSkippedError("no_rule_id")

    platforms = _platforms(raw.get("tags"))
    return DetectionRule(
        external_id=str(rule_id),
        name=raw.get("name") or str(rule_id),
        description=raw.get("description") or None,
        pattern=pattern,
        pattern_type=pattern_type,
        enabled=bool(raw.get("enabled")),
        created_at=parse_timestamp(raw.get("created_at")),
        modified_at=parse_timestamp(raw.get("updated_at")),
        level=normalize_level(raw.get("severity")),
        logsource={"product": platforms[0]} if len(platforms) == 1 else None,
        platforms=platforms,
        techniques=_techniques(raw.get("threat")),
        url=rule_url(str(raw["id"])) if raw.get("id") else None,
    )
