"""Elastic Security detection rule -> ``DetectionRule``."""

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
# Language of the rule types that do not state one.
_DEFAULT_LANGUAGES = {"eql": "eql", "esql": "esql"}
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
    pattern_type = PATTERN_TYPES.get(str(language).lower())
    if pattern_type is None:
        raise RuleSkippedError(f"language_{language}")
    rule_id = raw.get("rule_id")
    if not rule_id:
        raise RuleSkippedError("no_rule_id")

    platforms = _platforms(raw.get("tags"))
    return DetectionRule(
        key=str(rule_id),
        external_id=str(rule_id),
        name=raw.get("name") or str(rule_id),
        description=raw.get("description") or None,
        pattern=str(query),
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
