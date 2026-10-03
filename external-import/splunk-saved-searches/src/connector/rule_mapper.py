"""Splunk saved search -> ``DetectionRule``."""

import json
import re
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
_SEPARATORS_RE = re.compile(r"[\s,;|]+")
# Saved search setting holding the ATT&CK annotations (JSON object).
ANNOTATIONS_KEY = "action.correlationsearch.annotations"


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


def is_running(content: dict[str, Any]) -> bool:
    """Tell whether the saved search runs: enabled and scheduled."""
    return not is_true(content.get("disabled")) and is_true(content.get("is_scheduled"))


def annotation_techniques(annotations: Any) -> dict[str, str | None]:
    """Return the techniques of the ``mitre_attack`` annotation.

    ``annotations`` is the JSON object of ``action.correlationsearch.annotations``
    (a string, or already decoded). ``mitre_attack`` holds a list of technique
    ids or a single string; each value may hold several ids (separated by
    commas, semicolons, pipes or spaces) or ATT&CK links.
    """
    if isinstance(annotations, str):
        try:
            annotations = json.loads(annotations) if annotations.strip() else {}
        except json.JSONDecodeError:
            return {}
    if not isinstance(annotations, dict):
        return {}
    mitre_attack = annotations.get("mitre_attack") or []
    if isinstance(mitre_attack, str):
        mitre_attack = [mitre_attack]
    if not isinstance(mitre_attack, list):
        return {}
    found: list[str] = []
    for value in mitre_attack:
        text = str(value)
        found.extend(
            mitre_id
            for mitre_id in map(normalize_technique_id, _SEPARATORS_RE.split(text))
            if mitre_id
        )
        found.extend(extract_technique_ids(text))
    return {mitre_id: None for mitre_id in dict.fromkeys(found)}


def is_annotated(content: dict[str, Any]) -> bool:
    """Tell whether the saved search is annotated with ATT&CK techniques."""
    return bool(annotation_techniques(content.get(ANNOTATIONS_KEY)))


def in_scope(content: dict[str, Any], scope: SearchScope) -> bool:
    """Tell whether the saved search belongs to the configured scope."""
    if scope == "all":
        return True
    if scope == "correlation_searches":
        return is_correlation_search(content)
    return is_correlation_search(content) or is_alert(content) or is_annotated(content)


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

    ATT&CK techniques come from the ``mitre_attack`` annotation; saved
    searches without it are searched for technique ids written in their
    name, label or description. The search is enabled when it runs (not
    disabled and scheduled).
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

    techniques = annotation_techniques(content.get(ANNOTATIONS_KEY)) or {
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
        enabled=is_running(content),
        modified_at=parse_timestamp(entry.get("updated")),
        level=_level(content),
        techniques=techniques,
        url=url_for(entry),
    )
