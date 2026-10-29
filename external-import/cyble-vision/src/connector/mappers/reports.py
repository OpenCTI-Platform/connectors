"""Alert-side notices for catalog documents.

Engine APIs own the real Reports (advisory, newsfeed, newsflash).
Alerts for those services, and research-lab pointers, become Incidents.
"""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connectors_sdk.models import BaseIdentifiedEntity, Incident
from connectors_sdk.models.enums import IncidentType


class DocumentNoticeMapper(ServiceMapper):
    """Alert-side pointer that a catalog document exists."""

    services = ("advisory", "flash_report", "news_feed", "cyble_research_labs")

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        pointer = first_text(
            payload.get("report_id"),
            payload.get("value"),
            context.raw.get("title"),
            context.raw.get("keyword_name"),
            context.alert_id,
        )
        name = f"Cyble {context.service} available"
        if pointer:
            name = f"{name} - {pointer}"
        return [
            Incident(
                name=name,
                description=first_text(
                    context.description,
                    f"Document pointer from the Alerts API ({context.service}).",
                ),
                incident_type=IncidentType.ALERT,
                severity=context.severity,
                source="Cyble Vision",
                first_seen=context.created,
                last_seen=context.updated,
                **context.entity_kwargs(),
            )
        ]
