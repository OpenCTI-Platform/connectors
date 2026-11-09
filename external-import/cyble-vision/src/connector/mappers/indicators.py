"""Mappers for malicious infrastructure findings."""

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
from connectors_sdk.models import (
    BaseIdentifiedEntity,
    Incident,
    Indicator,
    IPV4Address,
)
from connectors_sdk.models.enums import IncidentType

_INCIDENT_TYPES = {
    "phishing": IncidentType.PHISHING,
    "suspicious_domains": IncidentType.TYPOSQUATTING,
}


class IndicatorsMapper(ServiceMapper):
    """Phishing, suspicious domains, and IP risk become indicators/observables.

    Each alert also gets its own Incident, related to those objects. The
    Indicator and observable are shared across alerts and sources, so only
    the Incident can carry this alert's severity and triage status.
    """

    services = (
        "phishing",
        "suspicious_domains",
        "ip_risk_score",
        "botnet",
        "malicious_ads",
        "iocs",
    )

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        raw = context.raw

        if context.service == "ip_risk_score":
            ip = first_text(
                raw.get("ip"),
                (
                    payload.get("value")
                    if not isinstance(payload.get("value"), list)
                    else None
                ),
            )
            if isinstance(payload.get("value"), list) and len(payload["value"]) >= 3:
                ip = first_text(payload["value"][2], ip)
            score = raw.get("new_risk_score")
            if not ip:
                return self._empty_fallback(context)
            kwargs = context.observable_kwargs()
            if isinstance(score, (int, float)):
                kwargs = {**kwargs, "score": max(0, min(100, int(score)))}
            observable = IPV4Address(value=ip, create_indicator=True, **kwargs)
            incident = self._incident(
                context,
                ip,
                labeled("Previous risk score", raw.get("old_risk_score")),
                labeled("New risk score", score),
            )
            return attach_related(incident, context, observable)

        if context.service == "iocs":
            ioc = first_text(raw.get("ioc"), payload.get("ioc"))
            observable = (
                observable_from_value(ioc, context, create_indicator=True)
                if ioc
                else None
            )
            if observable is None:
                return self._empty_fallback(context)
            return attach_related(self._incident(context, ioc), context, observable)

        domain = first_text(
            raw.get("domain"),
            payload.get("domain"),
            payload.get("domain_name"),
            payload.get("host_name"),
        )
        if not domain:
            return self._empty_fallback(context)
        observable = observable_from_value(domain, context, create_indicator=True)
        indicator = Indicator(
            name=domain,
            pattern=f"[domain-name:value = '{domain}']",
            pattern_type="stix",
            description=first_text(context.description, raw.get("llm_explanation")),
            labels=context.labels,
            author=context.author,
            markings=context.markings,
            external_references=context.external_references,
            created=context.created,
            valid_from=context.created,
        )
        return attach_related(
            self._incident(context, domain), context, observable, indicator
        )

    def _incident(self, context: AlertContext, value: str, *details: Any) -> Incident:
        return Incident(
            name=f"{context.service} - {value}",
            description=description_lines(
                context.description,
                context.raw.get("llm_explanation"),
                labeled("Keyword", context.asset),
                labeled("Value", value),
                *details,
            ),
            incident_type=_INCIDENT_TYPES.get(context.service, IncidentType.ALERT),
            severity=context.severity,
            source="Cyble Vision",
            first_seen=context.created,
            last_seen=context.updated,
            **context.entity_kwargs(),
        )

    def _empty_fallback(self, context: AlertContext) -> list[BaseIdentifiedEntity]:
        from connector.mappers.generic import GenericMapper

        return GenericMapper().map({}, context)
