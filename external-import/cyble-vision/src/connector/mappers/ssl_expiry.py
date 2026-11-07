"""Mapper for the ``ssl_expiry`` service."""

from __future__ import annotations

import json
from typing import Any

from connector.mappers.base import ServiceMapper
from connector.mappers.common import AlertContext, parse_datetime
from connector.mappers.observables import attach_related
from connectors_sdk.models import (
    BaseIdentifiedEntity,
    DomainName,
    Incident,
    Relationship,
    X509Certificate,
)
from connectors_sdk.models.enums import IncidentType


class SslExpiryMapper(ServiceMapper):
    """An expiring certificate on a customer-owned asset.

    No Indicator is created here. An Indicator asserts that a pattern is
    malicious, and the asset in these alerts belongs to the customer.
    """

    services = ("ssl_expiry",)

    def map(
        self, payload: dict[str, Any], context: AlertContext
    ) -> list[BaseIdentifiedEntity]:
        asset = payload.get("asset") or context.asset
        if not asset:
            raise ValueError("ssl_expiry alert has no asset")

        domain = DomainName(value=asset, **context.observable_kwargs())
        certificate = self._build_certificate(payload, context)
        incident = self._build_incident(payload, context, asset)

        objects = attach_related(incident, context, domain, certificate)
        if certificate:
            objects.append(
                Relationship(
                    type="related-to",
                    source=domain,
                    target=certificate,
                    author=context.author,
                    markings=context.markings,
                )
            )
        return objects

    def _build_certificate(
        self, payload: dict[str, Any], context: AlertContext
    ) -> X509Certificate | None:
        hashes = {}
        if payload.get("hash"):
            hashes["MD5"] = payload["hash"]
        if payload.get("fingerprint_sha256"):
            hashes["SHA-256"] = payload["fingerprint_sha256"]

        detail = payload.get("detail")
        if isinstance(detail, str):
            try:
                parsed = json.loads(detail)
            except json.JSONDecodeError:
                parsed = {}
            certificate = parsed.get("certificate") or {}
            if certificate.get("fingerprint_md5"):
                hashes["MD5"] = certificate["fingerprint_md5"]
            if certificate.get("fingerprint_sha256"):
                hashes["SHA-256"] = certificate["fingerprint_sha256"]
            if certificate.get("fingerprint_sha1"):
                hashes["SHA-1"] = certificate["fingerprint_sha1"]

        if not hashes:
            return None

        rsa = payload.get("rsa") or {}
        return X509Certificate(
            hashes=hashes,
            validity_not_before=parse_datetime(payload.get("issued")),
            validity_not_after=parse_datetime(payload.get("expiry")),
            subject_public_key_algorithm=payload.get("key_algorithm"),
            subject_public_key_exponent=rsa.get("exponent"),
            subject_public_key_modulus=rsa.get("modulus"),
            **context.observable_kwargs(),
        )

    def _build_incident(
        self, payload: dict[str, Any], context: AlertContext, asset: str
    ) -> Incident:
        days = payload.get("days")
        title = payload.get("title") or "SSL certificate expiring"
        description_parts = [context.description or title, f"Asset: {asset}"]
        if payload.get("port"):
            description_parts.append(f"Port: {payload['port']}")
        if days is not None:
            description_parts.append(f"Expires in {days} day(s)")
        if payload.get("expiry"):
            description_parts.append(f"Expiry: {payload['expiry']}")

        return Incident(
            name=f"{title} - {asset}",
            description="\n".join(description_parts),
            incident_type=IncidentType.ALERT,
            severity=context.severity,
            source="Cyble Vision",
            first_seen=context.created,
            last_seen=context.updated,
            **context.entity_kwargs(),
        )
