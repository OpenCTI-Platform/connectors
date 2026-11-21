"""Map an OpenCTI Incident update onto a Vision PUT /y/alerts body."""

from __future__ import annotations

from typing import Any, Collection

VISION_SOURCE = "Cyble Vision"
OCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

USER_SEVERITY = "user_severity"
STATUS = "status"
ALL_FIELDS = (USER_SEVERITY, STATUS)

# Last segment of the JSON-patch path that OpenCTI emits for each field.
# Workflow changes appear under the OpenCTI STIX extension, e.g.
# /extensions/extension-definition--…/workflow_id
_PATCH_FIELDS = {
    "severity": USER_SEVERITY,
    "workflow_id": STATUS,
    "x_opencti_workflow_id": STATUS,
}

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


def creator_ids(entity: dict[str, Any]) -> set[str]:
    """Return the IDs of the OpenCTI users who created the entity.

    Set by the platform, not by users: ``creators`` on a GraphQL read and
    ``creator_ids`` in the OpenCTI extension of a stream event. Unlike labels
    and external references, it proves which connector imported an Incident.
    """
    ids = {
        str(creator["id"])
        for creator in entity.get("creators") or []
        if isinstance(creator, dict) and creator.get("id")
    }
    extensions = entity.get("extensions")
    if isinstance(extensions, dict):
        octi = extensions.get(OCTI_EXTENSION)
        if isinstance(octi, dict):
            ids.update(str(i) for i in octi.get("creator_ids") or [] if i)
    return ids


def changed_fields(patch: Any) -> set[str]:
    """Return the Vision fields touched by an update event's JSON patch."""
    fields: set[str] = set()
    for operation in patch if isinstance(patch, list) else []:
        if not isinstance(operation, dict):
            continue
        key = str(operation.get("path") or "").rsplit("/", 1)[-1]
        if key in _PATCH_FIELDS:
            fields.add(_PATCH_FIELDS[key])
    return fields


def build_update(
    entity: dict[str, Any], fields: Collection[str] = ALL_FIELDS
) -> dict[str, str] | None:
    """Build a Vision update dict, or None when this is not a Cyble alert.

    Only ``fields`` are sent, so an analyst who changes severity does not
    also overwrite the Vision status (and vice versa).
    """
    alert_id = vision_alert_id(entity)
    service = vision_service(entity)
    if not alert_id or not service:
        return None

    update: dict[str, str] = {"id": alert_id, "service": service}
    if USER_SEVERITY in fields:
        severity = vision_severity(entity.get("severity"))
        if severity:
            update[USER_SEVERITY] = severity
    if STATUS in fields:
        status = vision_status(workflow_name_from_entity(entity))
        if status:
            update[STATUS] = status
    if USER_SEVERITY not in update and STATUS not in update:
        return None
    return update
