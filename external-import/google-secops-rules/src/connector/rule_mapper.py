"""Google SecOps rule and rule deployment -> ``DetectionRule``."""

import re
from typing import Any

from connector.attack_patterns import extract_technique_ids, normalize_technique_id
from connector.detection_rule import (
    DetectionRule,
    RuleSkippedError,
    normalize_level,
    parse_timestamp,
)
from secops_client import rule_id_from_name

# ``meta`` keys whose values are ATT&CK technique ids (``technique``,
# ``mitre_attack_technique``, ``mitre_attack_technique_id``, ``ttp``...).
_TECHNIQUE_KEY_RE = re.compile(r"mitre|att&?ck|technique|ttp", re.IGNORECASE)
_VALUE_SEPARATORS_RE = re.compile(r"[\s,;|]+")
# Rule names written as identifiers: ``mitre_attack_T1021_002_admin_share``.
_TECHNIQUE_IN_RULE_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9])T(\d{4})(?:[._](\d{3}))?(?!\d)"
)
# UDM event types matched by the ``events`` section of the rule.
_EVENT_TYPE_RE = re.compile(r"\.metadata\.event_type\s*=\s*\"([A-Z_]+)\"")

# UDM event type -> Sigma log source category of the telemetry it matches.
CATEGORIES = {
    "PROCESS_LAUNCH": "process_creation",
    "PROCESS_TERMINATION": "process_termination",
    "PROCESS_MODULE_LOAD": "image_load",
    "NETWORK_CONNECTION": "network_connection",
    "NETWORK_DNS": "dns_query",
    "NETWORK_HTTP": "proxy",
    "FILE_CREATION": "file_event",
    "FILE_MODIFICATION": "file_change",
    "FILE_DELETION": "file_delete",
    "FILE_OPEN": "file_access",
    "REGISTRY_CREATION": "registry_add",
    "REGISTRY_MODIFICATION": "registry_set",
    "REGISTRY_DELETION": "registry_delete",
}
# ``meta`` platform -> MITRE ATT&CK platform.
PLATFORMS = {
    "windows": "windows",
    "linux": "linux",
    "macos": "macos",
    "mac": "macos",
    "osx": "macos",
}


def _metadata(rule: dict[str, Any]) -> dict[str, str]:
    metadata = rule.get("metadata") or {}
    if not isinstance(metadata, dict):
        return {}
    return {str(key): str(value) for key, value in metadata.items() if value}


def techniques(rule: dict[str, Any]) -> dict[str, str | None]:
    """ATT&CK techniques of a rule, in order of appearance.

    Read from the ``meta`` section: every id of a technique key (``technique``,
    ``mitre_attack_technique``, ...), then the ids and ATT&CK links written in
    any value (``reference``, ``mitre_attack_url``, ``description``...), then
    the ids embedded in the rule name (``mitre_attack_T1021_002_...``).
    """
    metadata = _metadata(rule)
    found: list[str] = []
    for key, value in metadata.items():
        if _TECHNIQUE_KEY_RE.search(key):
            found.extend(
                mitre_id
                for mitre_id in map(
                    normalize_technique_id, _VALUE_SEPARATORS_RE.split(value)
                )
                if mitre_id
            )
    found.extend(extract_technique_ids(*metadata.values()))
    for match in _TECHNIQUE_IN_RULE_NAME_RE.finditer(
        str(rule.get("displayName") or "")
    ):
        technique, sub_technique = match.groups()
        found.append(f"T{technique}" + (f".{sub_technique}" if sub_technique else ""))
    return {mitre_id: None for mitre_id in dict.fromkeys(found)}


def logsource(rule: dict[str, Any]) -> dict[str, str] | None:
    """Sigma-like log source: category from the UDM event types, product from ``meta``."""
    result: dict[str, str] = {}
    event_types = set(_EVENT_TYPE_RE.findall(str(rule.get("text") or "")))
    categories = {CATEGORIES.get(event_type) for event_type in event_types}
    if len(categories) == 1 and None not in categories:
        result["category"] = categories.pop()
    platform = _metadata(rule).get("platform", "").strip().lower()
    if platform and re.fullmatch(r"[a-z0-9][a-z0-9 _-]*", platform):
        result["product"] = PLATFORMS.get(platform, platform.replace(" ", "_"))
    return result or None


def map_rule(rule: dict[str, Any], deployment: dict[str, Any] | None) -> DetectionRule:
    """Map a rule of the ``rules`` API with its ``RuleDeployment``.

    The rule is enabled when its deployment is (the rule is live). Archived
    rules cannot run and are left out; a rule without a deployment is not live.
    """
    rule_id = rule_id_from_name(rule.get("name"))
    if not rule_id:
        raise RuleSkippedError("no_rule_id")
    deployment = deployment or {}
    if deployment.get("archived"):
        raise RuleSkippedError("archived")
    text = rule.get("text")
    if not text or not str(text).strip():
        raise RuleSkippedError("no_text")
    metadata = _metadata(rule)
    rule_logsource = logsource(rule)
    platform = PLATFORMS.get((rule_logsource or {}).get("product", ""))
    severity = rule.get("severity")
    if isinstance(severity, dict):
        severity = severity.get("displayName")
    return DetectionRule(
        key=rule_id,
        external_id=rule_id,
        name=rule.get("displayName") or metadata.get("rule_name") or rule_id,
        description=metadata.get("description") or None,
        pattern=str(text),
        pattern_type="yara-l",
        enabled=bool(deployment.get("enabled")),
        created_at=parse_timestamp(rule.get("createTime")),
        modified_at=parse_timestamp(rule.get("revisionCreateTime")),
        level=normalize_level(severity) or normalize_level(metadata.get("severity")),
        logsource=rule_logsource,
        platforms=[platform] if platform else [],
        techniques=techniques(rule),
    )
