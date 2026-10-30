"""Helpers to turn Vision values into STIX observables."""

from __future__ import annotations

import ipaddress
from typing import Any

from connector.mappers.common import AlertContext
from connectors_sdk.models import (
    URL,
    BaseIdentifiedEntity,
    DomainName,
    IPV4Address,
    IPV6Address,
    Relationship,
)
from connectors_sdk.models.enums import RelationshipType


def observable_from_value(
    value: Any, context: AlertContext, *, create_indicator: bool = False
) -> BaseIdentifiedEntity | None:
    """Build an IP, domain, or URL observable from a string value."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
        if value is None:
            return None
    text = str(value).strip()
    if not text:
        return None

    kwargs = context.observable_kwargs()
    if create_indicator:
        kwargs = {**kwargs, "create_indicator": True}

    if text.startswith(("http://", "https://")):
        return URL(value=text, **kwargs)

    try:
        parsed = ipaddress.ip_address(text.split("/")[0])
    except ValueError:
        parsed = None

    if parsed is not None:
        if parsed.version == 4:
            return IPV4Address(value=text, **kwargs)
        return IPV6Address(value=text, **kwargs)

    if "." in text or text.endswith(".onion"):
        return DomainName(value=text.rstrip("."), **kwargs)
    return None


def attach_related(
    source: BaseIdentifiedEntity,
    context: AlertContext,
    *targets: BaseIdentifiedEntity | None,
    relationship_type: RelationshipType = RelationshipType.RELATED_TO,
) -> list[BaseIdentifiedEntity]:
    """Return source, each target, and a relationship from source to target.

    OpenCTI only shows entities on an Incident page when a relationship
    exists. Sending them in the same bundle is not enough.
    """
    objects: list[BaseIdentifiedEntity] = [source]
    seen: set[str] = set()
    for target in targets:
        if target is None:
            continue
        stix_id = target.to_stix2_object()["id"]
        if stix_id in seen:
            continue
        seen.add(stix_id)
        objects.append(target)
        objects.append(
            Relationship(
                type=relationship_type,
                source=source,
                target=target,
                author=context.author,
                markings=context.markings,
            )
        )
    return objects
