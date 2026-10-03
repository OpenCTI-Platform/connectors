"""Splunk saved search -> ``DetectionRule``."""

import json
from collections.abc import Callable
from typing import Any, Literal

from connector.attack_patterns import extract_technique_ids, normalize_technique_id
from connector.detection_rule import (
    DetectionRule,
    RuleSkippedError,
    normalize_level,
    parse_timestamp,
)

SearchScope = Literal["correlation_searches", "alerts", "all"]

# ``alert.severity`` (1 debug, 2 info, 3 warn, 4 error, 5 severe, 6 fatal).
ALERT_SEVERITY_LEVELS = {
    1: "informational",
    2: "informational",
    3: "low",
    4: "medium",
    5: "high",
    6: "critical",
}
_TRUE_VALUES = {"1", "true", "t", "yes", "y", "on"}


def is_true(value: Any) -> bool:
    """Read a Splunk boolean, sent as a JSON boolean, a number or a string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in _TRUE_VALUES


def is_correlation_search(content: dict[str, Any]) -> bool:
    """Tell whether the saved search is an Enterprise Security correlation search."""
    return is_true(content.get("action.correlationsearch.enabled"))


def is_alert(content: dict[str, Any]) -> bool:
    """Tell whether the saved search is scheduled and triggers alert actions."""
    return is_true(content.get("is_scheduled")) and (
        bool(str(content.get("actions") or "").strip())
        or is_true(content.get("alert.track"))
    )


def in_scope(content: dict[str, Any], scope: SearchScope) -> bool:
    """Tell whether the saved search belongs to the configured scope."""
    if scope == "all":
        return True
    if scope == "correlation_searches":
        return is_correlation_search(content)
    return is_correlation_search(content) or is_alert(content)


def _annotation_techniques(annotations: Any) -> dict[str, str | None]:
    if isinstance(annotations, str):
        try:
            annotations = json.loads(annotations) if annotations.strip() else {}
        except json.JSONDecodeError:
            return {}
    if not isinstance(annotations, dict):
        return {}
    techniques: dict[str, str | None] = {}
    mitre_attack = annotations.get("mitre_attack") or []
    if isinstance(mitre_attack, str):
        mitre_attack = [mitre_attack]
    for value in mitre_attack:
        mitre_id = normalize_technique_id(value)
        if mitre_id:
            techniques[mitre_id] = None
    return techniques


def _level(content: dict[str, Any]) -> str | None:
    level = normalize_level(content.get("action.notable.param.severity"))
    if level:
        return level
    try:
        return ALERT_SEVERITY_LEVELS.get(int(content.get("alert.severity")))
    except (TypeError, ValueError):
        return None


def rule_key(app: str, owner: str, name: str) -> str:
    """Return the unique key of a saved search: ``<app>/<owner>/<name>``."""
    return f"{app}/{owner}/{name}"


def name_from_key(key: str) -> str:
    """Return the saved search name of a rule key."""
    return key.split("/", 2)[-1]


def map_saved_search(
    entry: dict[str, Any],
    scope: SearchScope,
    url_for: Callable[[dict[str, Any]], str | None],
) -> DetectionRule:
    """Map an entry of ``/servicesNS/<owner>/<app>/saved/searches``.

    ATT&CK techniques come from the correlation search annotations
    (``mitre_attack``); saved searches without them are searched for
    technique ids written in their name or description.
    """
    name = entry.get("name")
    if not name:
        raise RuleSkippedError("no_name")
    content = entry.get("content") or {}
    if not in_scope(content, scope):
        raise RuleSkippedError("out_of_scope")
    search = content.get("search")
    if not search or not str(search).strip():
        raise RuleSkippedError("no_query")
    acl = entry.get("acl") or {}
    label = content.get("action.correlationsearch.label") or None
    description = content.get("description") or None

    techniques = _annotation_techniques(
        content.get("action.correlationsearch.annotations")
    ) or {
        mitre_id: None
        for mitre_id in extract_technique_ids(str(name), label, description)
    }
    return DetectionRule(
        key=rule_key(acl.get("app") or "-", acl.get("owner") or "-", str(name)),
        external_id=str(name),
        name=label or str(name),
        description=description,
        pattern=str(search),
        pattern_type="spl",
        enabled=not is_true(content.get("disabled")),
        modified_at=parse_timestamp(entry.get("updated")),
        level=_level(content),
        techniques=techniques,
        url=url_for(entry),
    )
