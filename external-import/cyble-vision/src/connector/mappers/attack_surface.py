"""Mappers for customer-owned attack-surface findings."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connector.mappers.observables import attach_related, observable_from_value
from connectors_sdk.models import BaseIdentifiedEntity, Incident
from connectors_sdk.models.enums import IncidentType


class AttackSurfaceMapper(ServiceMapper):
    """Customer assets become observables. No Indicator is created."""

    services = (
        "assets",
        "subdomains",
        "domain_expiry",
        "domain_watchlist",
        "new_port",
        "web_applications",
    )

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw
        value = first_text(
            raw.get("asset"),
            raw.get("subdomain"),
            raw.get("domain"),
            raw.get("ip"),
            raw.get("host"),
            payload.get("value"),
            payload.get("domain"),
            payload.get("ip"),
            payload.get("host"),
        )
        title = first_text(
            raw.get("title"), payload.get("title"), payload.get("type_text")
        )
        objects: list[BaseIdentifiedEntity] = []

        observable = observable_from_value(value, context)
        if observable:
            objects.append(observable)

        if context.service in {
            "domain_expiry",
            "new_port",
            "web_applications",
            "domain_watchlist",
        }:
            incident = Incident(
                name=title or f"{context.service} - {value or context.asset}",
                description=first_text(context.description, title),
                incident_type=IncidentType.ALERT,
                severity=context.severity,
                source="Cyble Vision",
                first_seen=context.created,
                last_seen=context.updated,
                **context.entity_kwargs(),
            )
            return attach_related(incident, context, observable)
        if not objects:
            from connector.mappers.generic import GenericMapper

            return GenericMapper().map(payload, context)

        return objects
