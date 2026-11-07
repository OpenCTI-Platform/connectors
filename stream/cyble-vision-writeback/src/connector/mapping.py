"""Map an OpenCTI Incident update onto a Vision PUT /y/alerts body."""

from __future__ import annotations

from typing import Any

VISION_SOURCE = "Cyble Vision"

SEVERITY_MAP = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

# Short OpenCTI workflow names → Vision status.
STATUS_MAP = {
    "new": "UNREVIEWED",
    "open": "UNREVIEWED",
    "in progress": "UNDER_REVIEW",
    "in-progress": "UNDER_REVIEW",
    "in_progress": "UNDER_REVIEW",
    "progress": "UNDER_REVIEW",
    "closed": "RESOLVED",
    "resolved": "RESOLVED",
    "done": "RESOLVED",
}


def _ref_get(ref: Any, key: str) -> Any:
    if isinstance(ref, dict):
        return ref.get(key)
    return getattr(ref, key, None)


def _iter_external_refs(entity: dict[str, Any]) -> list[Any]:
    refs = entity.get("external_references") or entity.get("externalReferences") or []
    if isinstance(refs, dict):
        refs = [edge.get("node") for edge in refs.get("edges") or []]
    return [ref for ref in refs if ref is not None]


def _iter_label_texts(entity: dict[str, Any]) -> list[str]:
    raw = (
        entity.get("labels")
        or entity.get("objectLabel")
        or entity.get("object_label")
        or []
    )
    if isinstance(raw, dict):
        raw = [edge.get("node") for edge in raw.get("edges") or []]
    texts: list[str] = []
    for label in raw:
        if isinstance(label, str):
            texts.append(label)
        elif isinstance(label, dict):
            texts.append(str(label.get("value") or label.get("name") or ""))
        else:
            texts.append(str(getattr(label, "value", "") or ""))
    return texts


def vision_alert_id(entity: dict[str, Any]) -> str | None:
    """Return the Vision alert UUID stored on the Incident."""
    for ref in _iter_external_refs(entity):
        if _ref_get(ref, "source_name") == VISION_SOURCE and _ref_get(
            ref, "external_id"
        ):
            return str(_ref_get(ref, "external_id"))
    return None


def vision_service(entity: dict[str, Any]) -> str | None:
    """Return the Vision service from labels such as ``cyble:github``."""
    for text in _iter_label_texts(entity):
        text = text.strip()
        if text.startswith("cyble:") and not text.startswith("cyble:bucket:"):
            name = text[len("cyble:") :]
            if name and not name.startswith("engine:") and name != "engine":
                return name
    return None


def vision_severity(value: Any) -> str | None:
    if value is None:
        return None
    return SEVERITY_MAP.get(str(value).strip().lower())


def vision_status(workflow_name: Any) -> str | None:
    if workflow_name is None:
        return None
    return STATUS_MAP.get(str(workflow_name).strip().lower())


def workflow_name_from_entity(entity: dict[str, Any]) -> str | None:
    """Read the OpenCTI workflow template name from an Incident payload."""
    status = entity.get("status")
    if isinstance(status, dict):
        template = status.get("template") or {}
        if isinstance(template, dict) and template.get("name"):
            return str(template["name"])
        if status.get("name"):
            return str(status["name"])
    return None


def build_update(entity: dict[str, Any]) -> dict[str, str] | None:
    """Build a Vision update dict, or None when this is not a Cyble alert."""
    alert_id = vision_alert_id(entity)
    service = vision_service(entity)
    if not alert_id or not service:
        return None

    update: dict[str, str] = {"id": alert_id, "service": service}
    severity = vision_severity(entity.get("severity"))
    status = vision_status(workflow_name_from_entity(entity))
    if severity:
        update["user_severity"] = severity
    if status:
        update["status"] = status
    if "user_severity" not in update and "status" not in update:
        return None
    return update
