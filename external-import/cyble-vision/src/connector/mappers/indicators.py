"""Mappers for malicious infrastructure findings."""

from __future__ import annotations

from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, first_text
from connector.mappers.observables import observable_from_value
from connectors_sdk.models import BaseIdentifiedEntity, Indicator, IPV4Address


class IndicatorsMapper(ServiceMapper):
    """Phishing, suspicious domains, and IP risk become indicators/observables."""

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
        objects: list[BaseIdentifiedEntity] = []

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
            if ip:
                kwargs = context.observable_kwargs()
                if isinstance(score, (int, float)):
                    kwargs = {**kwargs, "score": max(0, min(100, int(score)))}
                objects.append(IPV4Address(value=ip, create_indicator=True, **kwargs))
            return objects

        if context.service == "iocs":
            ioc = first_text(raw.get("ioc"), payload.get("ioc"))
            if ioc:
                observable = observable_from_value(ioc, context, create_indicator=True)
                if observable:
                    objects.append(observable)
            return objects or self._empty_fallback(context, ioc)

        domain = first_text(
            raw.get("domain"),
            payload.get("domain"),
            payload.get("domain_name"),
            payload.get("host_name"),
        )
        if domain:
            observable = observable_from_value(domain, context, create_indicator=True)
            if observable:
                objects.append(observable)
            objects.append(
                Indicator(
                    name=domain,
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    description=first_text(
                        context.description, raw.get("llm_explanation")
                    ),
                    labels=context.labels,
                    author=context.author,
                    markings=context.markings,
                    external_references=context.external_references,
                    created=context.created,
                    valid_from=context.created,
                )
            )
        return objects or self._empty_fallback(context, domain)

    def _empty_fallback(self, context: AlertContext, domain: str | None):
        if domain:
            return []
        from connector.mappers.generic import GenericMapper

        return GenericMapper().map({}, context)
