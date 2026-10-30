"""Mappers for CVE and product / host vulnerability alerts."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connector.mappers.observables import attach_related, observable_from_value
from connectors_sdk.models import BaseIdentifiedEntity, Incident, Vulnerability
from connectors_sdk.models.enums import IncidentType


class VulnerabilitiesMapper(ServiceMapper):
    """CVE-bearing alerts become Vulnerability objects.

    Host findings without a CVE stay as Incidents plus the host/IP.
    """

    services = (
        "new_vulnerability",
        "product_vulnerability",
        "vulnerability",
    )

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw
        cve = first_text(
            raw.get("cve"),
            payload.get("cve_id"),
            (
                payload.get("value")
                if str(payload.get("value", "")).startswith("CVE-")
                else None
            ),
        )
        title = first_text(raw.get("title"), payload.get("title"), cve)
        description = first_text(context.description, payload.get("description"), title)

        if cve:
            primary = Vulnerability(
                name=cve,
                description=description,
                **context.entity_kwargs(),
            )
        else:
            primary = Incident(
                name=title or f"Vulnerability finding - {context.asset}",
                description=description,
                incident_type=IncidentType.ALERT,
                severity=context.severity,
                source="Cyble Vision",
                first_seen=context.created,
                last_seen=context.updated,
                **context.entity_kwargs(),
            )

        observable = None
        for value in (
            raw.get("ip"),
            raw.get("host"),
            payload.get("ip"),
            payload.get("host"),
        ):
            observable = observable_from_value(value, context)
            if observable:
                break

        return attach_related(primary, context, observable)
