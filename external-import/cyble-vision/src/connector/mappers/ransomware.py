"""Mappers for ransomware victim and gang-update alerts."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connector.mappers.observables import attach_related
from connectors_sdk.models import BaseIdentifiedEntity, Incident, IntrusionSet
from connectors_sdk.models.enums import IncidentType


class RansomwareMapper(ServiceMapper):
    """Ransomware mentions become Incidents, with the actor as an Intrusion Set."""

    services = ("ransomware_updates", "darkweb_ransomware")

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw
        victim = first_text(raw.get("victim"), payload.get("victim"))
        actor = first_text(
            raw.get("threat_actor"), payload.get("threat_actor"), payload.get("gang")
        )
        name = first_text(
            f"Ransomware - {victim}" if victim else None,
            f"Ransomware - {actor}" if actor else None,
            "Cyble ransomware alert",
        )

        incident = Incident(
            name=name or "Cyble ransomware alert",
            description=first_text(
                context.description,
                payload.get("description"),
                raw.get("llm_explanation"),
            ),
            incident_type=IncidentType.RANSOMWARE,
            severity=context.severity,
            source="Cyble Vision",
            first_seen=context.created,
            last_seen=context.updated,
            **context.entity_kwargs(),
        )
        actor_entity = None
        if actor:
            actor_entity = IntrusionSet(
                name=actor,
                **context.entity_kwargs(),
            )
        return attach_related(incident, context, actor_entity)
