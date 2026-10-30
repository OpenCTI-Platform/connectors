"""Fallback mapper for services that have no dedicated mapper yet."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import (
    AlertContext,
    description_lines,
    first_text,
    labeled,
)
from connectors_sdk.models import BaseIdentifiedEntity, Incident
from connectors_sdk.models.enums import IncidentType

_SKIP_PAYLOAD_KEYS = {
    "created_at",
    "updated_at",
    "timestamp",
    "unique_key",
    "id",
    "_id",
    "data",
}


class GenericMapper(ServiceMapper):
    """Maps any alert using envelope fields plus a best-effort title."""

    services = ("*",)

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        title = first_text(
            context.raw.get("title"),
            payload.get("title"),
            f"Cyble Vision alert: {context.service}",
        )
        name = f"{title} - {context.asset}" if context.asset and title else title

        payload_fields = []
        for key, value in payload.items():
            if key in _SKIP_PAYLOAD_KEYS or not isinstance(value, (str, int, float)):
                continue
            field = labeled(key, value)
            if field:
                payload_fields.append(field)
            if len(payload_fields) >= 8:
                break

        return [
            Incident(
                name=name,
                description=description_lines(
                    context.description,
                    labeled("Keyword", context.asset),
                    *payload_fields,
                )
                or title,
                incident_type=IncidentType.ALERT,
                severity=context.severity,
                source="Cyble Vision",
                first_seen=context.created,
                last_seen=context.updated,
                **context.entity_kwargs(),
            )
        ]
