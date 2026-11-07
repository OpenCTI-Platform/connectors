"""Mappers for mentions, leaks, and public-code exposure."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import (
    AlertContext,
    description_lines,
    first_text,
    labeled,
)
from connector.mappers.observables import attach_related, observable_from_value
from connectors_sdk.models import BaseIdentifiedEntity, Incident, IntrusionSet
from connectors_sdk.models.enums import IncidentType


class ExposureMapper(ServiceMapper):
    """Code leaks, paste sites, forums, and social mentions become Incidents."""

    services = (
        "github",
        "bit_bucket",
        "postman",
        "docker",
        "cloud_storage",
        "pastebin",
        "telegram_mentions",
        "discord",
        "social_media_monitoring",
        "cyber_crime_forums",
        "darkweb_marketplaces",
        "hacktivism",
        "i2p",
        "tor_links",
        "physical_threats",
        "ot_ics",
        "osint",
        "defacement_content",
        "defacement_keyword",
        "defacement_url",
        "mobile_apps",
    )

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw
        attacker = first_text(payload.get("attacker"), raw.get("attacker"))
        team = first_text(payload.get("team"), raw.get("team"))
        alert_type = first_text(raw.get("type"), payload.get("type"))
        keyword = first_text(context.asset, raw.get("keyword_name"))
        url = first_text(
            raw.get("url"),
            payload.get("html_url"),
            payload.get("url"),
            payload.get("website_url"),
            payload.get("i2p_url"),
        )
        ip = first_text(payload.get("ip"), raw.get("ip"))
        source_website = first_text(payload.get("source_website"))

        title = first_text(
            raw.get("title"),
            payload.get("title"),
            raw.get("filename"),
            raw.get("chat_title"),
            " - ".join(
                part
                for part in (alert_type or context.service, attacker or team, keyword)
                if part
            ),
            url,
            f"Cyble Vision alert: {context.service}",
        )
        description = description_lines(
            context.description,
            raw.get("llm_explanation"),
            payload.get("description"),
            payload.get("message"),
            labeled("Keyword", keyword),
            labeled("Type", alert_type),
            labeled("Attacker", attacker),
            labeled("Team", team),
            labeled("Country", payload.get("country_name")),
            labeled("Source", source_website),
            labeled("Server", payload.get("server")),
            labeled("URL", url),
            labeled("IP", ip),
        )

        incident_type = IncidentType.DATA_LEAK
        if context.service == "hacktivism" or context.service.startswith("defacement"):
            incident_type = IncidentType.REPUTATION_DAMAGE
        elif context.service not in {"github", "cloud_storage", "pastebin", "postman"}:
            incident_type = IncidentType.ALERT

        incident = Incident(
            name=title or f"Cyble Vision alert: {context.service}",
            description=description,
            incident_type=incident_type,
            severity=context.severity,
            source="Cyble Vision",
            first_seen=context.created,
            last_seen=context.updated,
            **context.entity_kwargs(),
        )

        related: list[BaseIdentifiedEntity] = []
        for value in (url, ip, source_website):
            observable = observable_from_value(value, context)
            if observable:
                related.append(observable)

        actor_name = first_text(team, attacker)
        if actor_name:
            related.append(
                IntrusionSet(
                    name=actor_name,
                    **context.entity_kwargs(),
                )
            )

        return attach_related(incident, context, *related)
