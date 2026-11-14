"""Attach the full Vision alert as an OpenCTI Note.

Per-service mappers pick graph objects (IP, URL, actor). This module keeps
every remaining field so analysts can open Notes and see the original alert.
Credentials are already masked by ``redaction`` before mapping starts.
"""

from __future__ import annotations

import json
from typing import Any

from connector.mappers.common import AlertContext
from connectors_sdk.models import BaseIdentifiedEntity, Note
from connectors_sdk.models.enums import NoteType

# Fields that change on triage, in Vision or through write-back. The Note ID is
# derived from its content, so keeping them would create a new Note each time.
_VOLATILE_KEYS = {
    "status",
    "user_severity",
    "true_positive",
    "assignee_id",
    "assignment_date",
    "updated_at",
    "updated_by_id",
    "archive_date",
    "deleted_at",
}
_SKIP_TABLE_KEYS = _VOLATILE_KEYS | {
    "company_id",
    "entity_id",
    "entity_type",
    "data",
}
_TABLE_VALUE_LIMIT = 500
_JSON_LIMIT = 20000


def attach_details_note(
    objects: list[BaseIdentifiedEntity], context: AlertContext
) -> list[BaseIdentifiedEntity]:
    """Append a Note containing the full alert to the primary object."""
    primary = _primary_entity(objects)
    if primary is None:
        return objects

    snapshot = _stable_snapshot(context.raw)
    objects.append(
        Note(
            abstract=f"Cyble Vision alert details ({context.service})",
            content=_format_note(snapshot, context.service),
            created=context.created,
            authors=["Cyble Vision"],
            note_types=[NoteType.EXTERNAL],
            objects=[primary],
            author=context.author,
            markings=context.markings,
            labels=context.labels,
            external_references=context.external_references,
        )
    )
    return objects


def _primary_entity(
    objects: list[BaseIdentifiedEntity],
) -> BaseIdentifiedEntity | None:
    for entity in objects:
        entity_type = entity.to_stix2_object()["type"]
        if entity_type not in {"relationship", "note", "marking-definition"}:
            return entity
    return None


def _stable_snapshot(alert: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in alert.items() if key not in _VOLATILE_KEYS}


def _format_note(alert: dict[str, Any], service: str) -> str:
    rows = [
        f"- **Service:** {service}",
        f"- **Alert ID:** {alert.get('id') or ''}",
        f"- **Keyword:** {alert.get('keyword_name') or alert.get('asset') or ''}",
        f"- **Severity:** {alert.get('user_severity') or alert.get('severity') or ''}",
    ]
    table_rows = _table_rows(alert)
    json_block = json.dumps(alert, default=str, indent=2, ensure_ascii=False)
    if len(json_block) > _JSON_LIMIT:
        json_block = json_block[:_JSON_LIMIT] + "\n… (truncated)"

    sections = [
        "## Cyble Vision alert",
        "\n".join(rows),
        "## Fields",
        "| Field | Value |",
        "| --- | --- |",
        *table_rows,
        "## Raw JSON",
        f"```json\n{json_block}\n```",
    ]
    return "\n\n".join(sections)


def _table_rows(alert: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for path, value in _flatten(alert):
        key = path.split(".")[-1]
        if key in _SKIP_TABLE_KEYS or value in (None, "", [], {}):
            continue
        text = str(value).replace("\n", " ").replace("|", "\\|")
        if len(text) > _TABLE_VALUE_LIMIT:
            text = text[:_TABLE_VALUE_LIMIT] + "…"
        rows.append(f"| `{path}` | {text} |")
    return rows or ["| _(none)_ | |"]


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        items: list[tuple[str, Any]] = []
        for key, inner in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            items.extend(_flatten(inner, path))
        return items
    if isinstance(value, list):
        if not value or all(not isinstance(item, (dict, list)) for item in value):
            return [(prefix, ", ".join(str(item) for item in value))] if value else []
        items = []
        for index, inner in enumerate(value):
            items.extend(_flatten(inner, f"{prefix}[{index}]"))
        return items
    return [(prefix, value)]
