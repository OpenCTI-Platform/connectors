"""CrowdStrike Falcon custom IOA rule -> ``DetectionRule``."""

import json
from typing import Any

from connector.attack_patterns import extract_technique_ids
from connector.detection_rule import (
    DetectionRule,
    RuleSkippedError,
    normalize_level,
    parse_timestamp,
)

# Rule group ``platform`` -> MITRE ATT&CK platform.
PLATFORMS = {"windows": "windows", "mac": "macos", "linux": "linux"}
# Rule type -> Sigma log source category of the telemetry it matches.
CATEGORIES = {
    "process creation": "process_creation",
    "file creation": "file_event",
    "network connection": "network_connection",
    "domain name": "dns_query",
}
_FIELD_VALUE_KEYS = ("name", "label", "type", "values", "final_value")


def rule_pattern(rule: dict[str, Any]) -> str:
    """Serialize the logic of a custom IOA rule as canonical JSON.

    The rule type, the action taken and the field values are what the
    sensor matches on; their canonical form is the Indicator pattern, so the
    Indicator only changes when the logic does.
    """
    field_values = sorted(
        (
            {key: field.get(key) for key in _FIELD_VALUE_KEYS if key in field}
            for field in rule.get("field_values") or []
            if isinstance(field, dict)
        ),
        key=lambda field: (str(field.get("name")), str(field.get("label"))),
    )
    return json.dumps(
        {
            "ruletype_id": rule.get("ruletype_id"),
            "ruletype_name": rule.get("ruletype_name"),
            "disposition_id": rule.get("disposition_id"),
            "action_label": rule.get("action_label"),
            "field_values": field_values,
        },
        sort_keys=True,
        indent=2,
    )


def rule_key(rule_group_id: str, instance_id: str) -> str:
    """Return the unique key of a rule: ``<rule group id>/<instance id>``."""
    return f"{rule_group_id}/{instance_id}"


def instance_id_from_key(key: str) -> str:
    """Return the rule instance id of a rule key."""
    return key.split("/", 1)[-1]


def _techniques(group: dict[str, Any], rule: dict[str, Any]) -> dict[str, str | None]:
    """Technique ids written in the rule, else in its rule group."""
    mitre_ids = extract_technique_ids(
        rule.get("name"), rule.get("description"), rule.get("comment")
    ) or extract_technique_ids(group.get("name"), group.get("description"))
    return {mitre_id: None for mitre_id in mitre_ids}


def _logsource(group: dict[str, Any], rule: dict[str, Any]) -> dict[str, str] | None:
    logsource: dict[str, str] = {}
    category = CATEGORIES.get(str(rule.get("ruletype_name") or "").strip().lower())
    if category:
        logsource["category"] = category
    platform = PLATFORMS.get(str(group.get("platform") or "").lower())
    if platform:
        logsource["product"] = platform
    return logsource or None


def map_rule(
    group: dict[str, Any], rule: dict[str, Any], enforced: bool = True
) -> DetectionRule:
    """Map a rule of a custom IOA rule group.

    CrowdStrike has no structured ATT&CK mapping for custom IOA rules: the
    technique ids written in the rule name, description and comment count,
    or those of the rule group name and description when the rule has none.
    The rule is enabled when the rule and its group are, and the group is
    ``enforced`` (assigned to an enabled prevention policy).
    """
    if group.get("deleted") or rule.get("deleted"):
        raise RuleSkippedError("deleted")
    instance_id = rule.get("instance_id")
    group_id = group.get("id")
    if not instance_id or not group_id:
        raise RuleSkippedError("no_rule_id")
    platform = PLATFORMS.get(str(group.get("platform") or "").lower())
    return DetectionRule(
        key=rule_key(str(group_id), str(instance_id)),
        external_id=str(instance_id),
        name=rule.get("name") or f"Custom IOA rule {instance_id}",
        description=rule.get("description") or None,
        pattern=rule_pattern(rule),
        pattern_type="crowdstrike-ioa",
        enabled=bool(rule.get("enabled")) and bool(group.get("enabled")) and enforced,
        created_at=parse_timestamp(rule.get("created_on")),
        modified_at=parse_timestamp(rule.get("modified_on")),
        level=normalize_level(rule.get("pattern_severity")),
        logsource=_logsource(group, rule),
        platforms=[platform] if platform else [],
        techniques=_techniques(group, rule),
    )


def iter_rules(
    groups: list[dict[str, Any]],
    enforced_group_ids: set[str] | None = None,
) -> list[tuple[dict[str, Any], dict[str, Any], bool]]:
    """Flatten rule groups into ``(group, rule, enforced)`` triples.

    ``enforced`` tells whether the group is assigned to an enabled
    prevention policy; every group counts as enforced when
    ``enforced_group_ids`` is ``None`` (assignments unknown).
    """
    return [
        (
            group,
            rule,
            enforced_group_ids is None or str(group.get("id")) in enforced_group_ids,
        )
        for group in groups
        for rule in group.get("rules") or []
        if isinstance(rule, dict)
    ]
