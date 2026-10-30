"""Service mapper registry and the single entry point for mapping an alert."""

from __future__ import annotations

from typing import Any

from connector.mappers.attack_surface import AttackSurfaceMapper
from connector.mappers.common import build_context, extract_payload
from connector.mappers.credentials import CredentialsMapper
from connector.mappers.details import attach_details_note
from connector.mappers.exposure import ExposureMapper
from connector.mappers.generic import GenericMapper
from connector.mappers.indicators import IndicatorsMapper
from connector.mappers.ransomware import RansomwareMapper
from connector.mappers.reports import DocumentNoticeMapper
from connector.mappers.ssl_expiry import SslExpiryMapper
from connector.mappers.vulnerabilities import VulnerabilitiesMapper
from connectors_sdk.models import (
    BaseIdentifiedEntity,
    OrganizationAuthor,
    TLPMarking,
)

DEFAULT_PORTAL_URL_TEMPLATE = 'https://cyble.ai/alerts/{service}?id=["{alert_id}"]'


def _build_registry() -> dict[str, object]:
    registry: dict[str, object] = {}
    for mapper in [
        SslExpiryMapper(),
        DocumentNoticeMapper(),
        CredentialsMapper(),
        VulnerabilitiesMapper(),
        IndicatorsMapper(),
        AttackSurfaceMapper(),
        ExposureMapper(),
        RansomwareMapper(),
    ]:
        for name in mapper.services:
            registry[name] = mapper
    return registry


MAPPERS = _build_registry()


class AlertConversionError(Exception):
    """Raised when a single alert cannot be converted to STIX."""


def map_alert(
    alert: dict[str, Any],
    author: OrganizationAuthor,
    marking: TLPMarking,
    portal_url_template: str = DEFAULT_PORTAL_URL_TEMPLATE,
) -> list[BaseIdentifiedEntity]:
    """Map one Vision alert to a list of STIX objects."""
    try:
        context = build_context(alert, author, marking, portal_url_template)
        payload = extract_payload(alert)
        mapper = MAPPERS.get(alert.get("service", ""), GenericMapper())
        return attach_details_note(mapper.map(payload, context), context)
    except Exception as e:
        raise AlertConversionError(
            f"Failed to convert alert {alert.get('id')} "
            f"(service={alert.get('service')}): {e}"
        ) from e
