"""Mappers for credential and stealer exposure."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connector.mappers.observables import attach_related, observable_from_value
from connectors_sdk.models import BaseIdentifiedEntity, Incident, Malware, UserAccount
from connectors_sdk.models.enums import IncidentType


class CredentialsMapper(ServiceMapper):
    """Compromised credentials and stealer logs become Incidents plus observables.

    Passwords are never written into STIX.
    """

    services = (
        "stealer_logs",
        "leaked_credentials",
        "compromised_files",
        "compromised_endpoints_cookies",
        "compromised_cards",
        "darkweb_data_breaches",
    )

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw
        content = (
            payload.get("content") if isinstance(payload.get("content"), dict) else {}
        )
        url = first_text(raw.get("url"), content.get("URL"), content.get("url"))
        username = first_text(
            raw.get("username"), content.get("Username"), content.get("username")
        )
        domain = first_text(
            raw.get("domain"),
            (
                (payload.get("content_related_info") or {}).get("domain")
                if isinstance(payload.get("content_related_info"), dict)
                else None
            ),
        )
        malware_family = first_text(raw.get("malware_family"))

        name = first_text(
            f"{context.service} - {username}" if username else None,
            f"{context.service} - {url}" if url else None,
            f"Cyble Vision alert: {context.service}",
        )
        description_parts = [
            context.description,
            f"Keyword: {raw.get('keyword_name')}" if raw.get("keyword_name") else None,
            f"URL: {url}" if url else None,
            f"Username: {username}" if username else None,
            f"Malware family: {malware_family}" if malware_family else None,
        ]

        incident_type = (
            IncidentType.DATA_LEAK
            if context.service == "darkweb_data_breaches"
            else IncidentType.COMPROMISE
        )
        incident = Incident(
            name=name or f"Cyble Vision alert: {context.service}",
            description="\n".join(part for part in description_parts if part),
            incident_type=incident_type,
            severity=context.severity,
            source="Cyble Vision",
            first_seen=context.created,
            last_seen=context.updated,
            **context.entity_kwargs(),
        )
        related: list[BaseIdentifiedEntity] = []

        for value in (url, domain):
            observable = observable_from_value(value, context)
            if observable:
                related.append(observable)

        if username:
            related.append(
                UserAccount(
                    account_login=username,
                    user_id=username,
                    **context.observable_kwargs(),
                )
            )

        if malware_family and malware_family.upper() != "NA":
            related.append(
                Malware(
                    name=malware_family,
                    is_family=True,
                    **context.entity_kwargs(),
                )
            )

        return attach_related(incident, context, *related)
