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
# ``pattern_type`` of a saved search whose detection logic is not its search alone.
RULE_PATTERN_TYPE = "splunk-rule"
# Trigger condition settings, applied by Splunk to the results of the search.
_TRIGGER_KEYS = ("alert_type", "alert_comparator", "alert_threshold", "alert_condition")


def _trigger(content: dict[str, Any]) -> dict[str, str]:
    """Return the trigger condition of a saved search, empty when it alerts on any result.

    A search alerting ``always`` or when its number of events is greater than
    0 alerts on its results: the search holds its whole detection logic.
    """
    trigger = {
        key: str(content[key]).strip()
        for key in _TRIGGER_KEYS
        if content.get(key) is not None and str(content[key]).strip()
    }
    alert_type = trigger.get("alert_type", "always").lower()
    if alert_type != "custom":
        trigger.pop("alert_condition", None)
    if alert_type == "always" or (
        alert_type == "number of events"
        and trigger.get("alert_comparator", "greater than").lower() == "greater than"
        and trigger.get("alert_threshold", "0") in ("0", "0.0")
    ):
        return {}
    return trigger


def rule_pattern(search: str, content: dict[str, Any]) -> tuple[str, str]:
    """Return the Indicator ``pattern`` and ``pattern_type`` of a saved search.

    The SPL search is the pattern when the saved search alerts on any result.
    Another trigger condition (a number of events, hosts or sources compared
    to a threshold, or a custom condition) is represented by the canonical
    JSON of the search and its trigger, under the ``splunk-rule`` pattern
    type: its Indicator changes with the trigger, and two saved searches
    sharing a search but not their trigger are two Indicators.
    """
    trigger = _trigger(content)
    if not trigger:
        return search, "spl"
    return (
        json.dumps({"search": search, **trigger}, sort_keys=True, indent=2),
        RULE_PATTERN_TYPE,
    )


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


def saved_search_id(app: str, owner: str, name: str) -> str:
    """Return the id of a saved search: ``<app>/<owner>/<name>``.

    Splunk only requires a name to be unique within its app and owner
    namespace, so the name alone can designate several saved searches.
    """
    return f"{app}/{owner}/{name}"


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
    pattern, pattern_type = rule_pattern(str(search), content)
    return DetectionRule(
        external_id=saved_search_id(
            acl.get("app") or "-", acl.get("owner") or "-", str(name)
        ),
        name=label or str(name),
        description=description,
        pattern=pattern,
        pattern_type=pattern_type,
        enabled=is_running(content),
        modified_at=parse_timestamp(entry.get("updated")),
        level=_level(content),
        techniques=techniques,
        url=url_for(entry),
    )
