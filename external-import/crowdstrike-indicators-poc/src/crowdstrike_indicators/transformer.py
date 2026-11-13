"""Convert CrowdStrike indicators into STIX 2.1 indicators, losing nothing."""

import ipaddress
import logging
from datetime import datetime
from typing import Any

from crowdstrike_indicators.errors import IndicatorConversionError
from crowdstrike_indicators.ids import (
    CROWDSTRIKE_NAMESPACE,
    indicator_id,
)
from crowdstrike_indicators.models import CrowdStrikeIndicator
from crowdstrike_indicators.stix import CrowdStrikeStix2Indicator
from stix2 import (
    EqualityComparisonExpression,
    KillChainPhase,
    ObjectPath,
    ObservationExpression,
    StringConstant,
)
from stix2.exceptions import STIXError

from shared.transformer import AbstractTransformer

__all__ = [
    "CROWDSTRIKE_NAMESPACE",
    "CrowdStrikeIndicatorTransformer",
    "build_pattern",
    "indicator_id",
    "x_property_name",
]

LOGGER = logging.getLogger(__name__)

# CrowdStrike indicator type -> STIX object type and property path. IP
# addresses are resolved separately, by version.
PATTERN_PATHS: dict[str, tuple[str, list[str]]] = {
    "domain": ("domain-name", ["value"]),
    "url": ("url", ["value"]),
    "hash_md5": ("file", ["hashes", "MD5"]),
    "hash_sha1": ("file", ["hashes", "SHA-1"]),
    "hash_sha256": ("file", ["hashes", "SHA-256"]),
}
IP_ADDRESS_TYPE = "ip_address"

# STIX 2.1 None/Low/Med/High confidence scale. "unverified" is absent on
# purpose: an indicator nobody assessed has no confidence, not a zero one.
CONFIDENCE = {"high": 85, "medium": 50, "low": 15}

KILL_CHAIN_NAME = "lockheed-martin-cyber-kill-chain"
# Same phase names as the existing CrowdStrike connector, so phases match
# those already in OpenCTI.
KILL_CHAIN_PHASES = {
    "Reconnaissance": "reconnaissance",
    "Weaponization": "weaponization",
    "Delivery": "delivery",
    "Exploitation": "exploitation",
    "Installation": "installation",
    "C2": "command-and-control",
    "ActionOnObjectives": "action-on-objectives",
}

SOURCE_NAME = "CrowdStrike"


X_PREFIX = "x_crowdstrike_"
X_EXTRA = f"{X_PREFIX}extra"

# Fields a native STIX property holds: never repeated in an ``x_`` property.
NATIVELY_HELD_FIELDS = frozenset(
    {"id", "indicator", "type", "last_updated", "published_date", "deleted"}
)


def build_pattern(item: CrowdStrikeIndicator) -> str:
    """Return the STIX pattern of ``item``, quoted and escaped by stix2.

    :raises IndicatorConversionError: if the type has no pattern mapping.
    """
    if item.type == IP_ADDRESS_TYPE:
        try:
            version = ipaddress.ip_address(item.indicator).version
        except ValueError as error:
            raise IndicatorConversionError(
                item.id, f"not an IP address: {item.indicator!r}"
            ) from error
        object_type = "ipv6-addr" if version == 6 else "ipv4-addr"
        path = ["value"]
    elif item.type in PATTERN_PATHS:
        object_type, path = PATTERN_PATHS[item.type]
    else:
        raise IndicatorConversionError(
            item.id, f"unsupported indicator type {item.type!r}"
        )
    comparison = EqualityComparisonExpression(
        ObjectPath(object_type, path), StringConstant(item.indicator)
    )
    return str(ObservationExpression(str(comparison)))


def x_property_name(field_name: str) -> str:
    """Return the ``x_crowdstrike_`` property keeping an API field."""
    return X_PREFIX + field_name.lstrip("_")


def _x_properties(item: CrowdStrikeIndicator, confidence: int | None) -> dict[str, Any]:
    """Keep the fields of ``item`` no native property holds.

    ``malicious_confidence`` is kept only when ``confidence`` could not be
    set, and ``kill_chains`` only when one of its values has no phase.
    """
    properties: dict[str, Any] = {}
    for name, field in CrowdStrikeIndicator.model_fields.items():
        value = getattr(item, name)
        if value is None or value == []:
            continue  # stix2 drops empty lists: absent and empty look the same
        if name in NATIVELY_HELD_FIELDS:
            continue
        if name == "malicious_confidence" and confidence is not None:
            continue
        if name == "kill_chains" and all(kc in KILL_CHAIN_PHASES for kc in value):
            continue
        if name == "labels":
            value = [
                label.model_dump(mode="json", exclude_none=True) for label in value
            ]
        properties[x_property_name(field.alias or name)] = value
    if item.model_extra:
        properties[X_EXTRA] = item.model_extra
    return properties


def _kill_chain_phases(item: CrowdStrikeIndicator) -> list[KillChainPhase]:
    phases = []
    for kill_chain in item.kill_chains or []:
        phase_name = KILL_CHAIN_PHASES.get(kill_chain)
        if phase_name is None:
            LOGGER.debug(
                "Indicator %s: unknown kill chain %r skipped", item.id, kill_chain
            )
            continue
        phases.append(
            KillChainPhase(kill_chain_name=KILL_CHAIN_NAME, phase_name=phase_name)
        )
    return phases


def _created(item: CrowdStrikeIndicator) -> datetime:
    created = item.published_date or item.last_updated
    if created > item.last_updated:
        raise IndicatorConversionError(
            item.id,
            f"published_date {created.isoformat()} is after "
            f"last_updated {item.last_updated.isoformat()}",
        )
    return created


class CrowdStrikeIndicatorTransformer(
    AbstractTransformer[CrowdStrikeIndicator, CrowdStrikeStix2Indicator]
):
    """Convert a CrowdStrike indicator into one STIX 2.1 indicator.

    The native STIX properties whose meaning matches are filled, and the
    CrowdStrike fields they cannot hold are kept in ``x_crowdstrike_*``
    properties, so nothing is lost. No network call is made.
    """

    def convert(self, item: CrowdStrikeIndicator) -> CrowdStrikeStix2Indicator:
        """Return the STIX indicator of ``item``.

        :raises IndicatorConversionError: if the type has no pattern mapping,
            if ``published_date`` is after ``last_updated``, or if stix2
            rejects the object.
        """
        pattern = build_pattern(item)
        created = _created(item)
        confidence = CONFIDENCE.get((item.malicious_confidence or "").lower())
        native: dict[str, Any] = {
            "pattern": pattern,
            "pattern_type": "stix",
            "name": item.indicator,
            "valid_from": created,
            "created": created,
            "modified": item.last_updated,
            "revoked": True if item.deleted else None,
            "confidence": confidence,
            "kill_chain_phases": _kill_chain_phases(item) or None,
            "labels": [label.name for label in item.labels or []] or None,
            "external_references": [
                {"source_name": SOURCE_NAME, "external_id": item.id}
            ],
        }
        properties = {
            name: value for name, value in native.items() if value is not None
        }
        properties.update(_x_properties(item, confidence))
        try:
            return CrowdStrikeStix2Indicator(id=indicator_id(item.id), **properties)
        except STIXError as error:
            raise IndicatorConversionError(item.id, str(error)) from error
