from __future__ import annotations

import logging
from typing import Any, Callable

from pycti import OpenCTIConnectorHelper

from .asn_enricher import AsnEnricher
from .domain_enricher import DomainEnricher
from .file_enricher import DEFAULT_SIGHTINGS_LIMIT, FileEnricher
from .ip_enricher import IpEnricher
from .stairwell import StairwellClient
from .stix_builder import TLP_IDS

logger = logging.getLogger(__name__)

_TLP_LEVELS = (
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
)


def normalize_max_tlp(value: str | None) -> str:
    """Return `value` as a canonical `TLP:*` level, or raise at startup.

    pycti's `check_max_tlp` raises KeyError on an unknown maximum, so the
    configured value is validated once here rather than on every message.
    """
    level = (value or "").strip().upper()
    if level and not level.startswith("TLP:"):
        level = f"TLP:{level}"
    if level not in _TLP_LEVELS:
        raise ValueError(
            f"CONNECTOR_MAX_TLP must be one of {', '.join(_TLP_LEVELS)}; "
            f"got {value!r}"
        )
    return level


def observable_tlps(observable: dict[str, Any]) -> list[str]:
    """TLP marking definitions on an OpenCTI observable (may be empty)."""
    out: list[str] = []
    for marking in observable.get("objectMarking") or []:
        if isinstance(marking, dict) and marking.get("definition_type") == "TLP":
            out.append(str(marking.get("definition") or ""))
    return out


# Standard TLP marking IDs to their level. CLEAR and WHITE share an ID, and
# both levels gate the same way.
_TLP_BY_MARKING_ID = {
    marking_id: f"TLP:{level.upper()}" for level, marking_id in TLP_IDS.items()
}


# Stands in for a marking whose type could not be determined. pycti does not
# recognise it, so the max-TLP check refuses it.
UNRESOLVED_MARKING = "TLP:UNRESOLVED"


def _marking_tlp(marking: dict[str, Any]) -> str | None:
    """The TLP level of a marking definition, "" if it is another kind of
    marking (PAP, statement), or None if its kind is not stated.

    Accepts the STIX form (`definition_type: tlp`, `definition: {tlp: red}`)
    and OpenCTI's forms (`definition_type` or `x_opencti_definition_type`
    `TLP`, with `definition` or `x_opencti_definition` `TLP:RED`).
    """
    kind = str(
        marking.get("x_opencti_definition_type") or marking.get("definition_type") or ""
    ).upper()
    if not kind:
        return None
    if kind != "TLP":
        return ""
    definition = marking.get("x_opencti_definition") or marking.get("definition")
    if isinstance(definition, dict):
        return f"TLP:{str(definition.get('tlp') or '').upper()}"
    return str(definition or UNRESOLVED_MARKING)


def stix_marking_tlps(
    entity: dict[str, Any],
    objects: list[dict[str, Any]],
    lookup: Callable[[str], dict[str, Any] | None] | None = None,
) -> list[str]:
    """TLP levels of a STIX object's `object_marking_refs` (may be empty).

    A ref resolves through the standard TLP marking IDs, a marking-definition
    object in `objects`, or `lookup` (OpenCTI's marking definitions). A
    marking of another kind, such as PAP, is not a TLP restriction. A ref
    that cannot be resolved yields `UNRESOLVED_MARKING`, which the gate
    refuses: it could be a RED marking.
    """
    definitions = {
        o.get("id"): o
        for o in objects
        if isinstance(o, dict) and o.get("type") == "marking-definition"
    }
    out: list[str] = []
    for ref in entity.get("object_marking_refs") or []:
        if ref in _TLP_BY_MARKING_ID:
            out.append(_TLP_BY_MARKING_ID[ref])
            continue
        level = _marking_tlp(definitions[ref]) if ref in definitions else None
        if level is None and lookup is not None:
            try:
                found = lookup(ref)
            except Exception:  # noqa: BLE001 - unresolvable means refused
                found = None
            if isinstance(found, dict):
                level = _marking_tlp(found)
        if level is None:
            out.append(UNRESOLVED_MARKING)
        elif level:
            out.append(level)
    return out


class Dispatcher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        variant_limit: int = 25,
        resolutions_limit: int = 50,
        sightings_limit: int = DEFAULT_SIGHTINGS_LIMIT,
        opencti_base_url: str = "http://localhost:8080",
        max_tlp: str = "TLP:AMBER",
    ) -> None:
        self.helper = helper
        self.max_tlp = normalize_max_tlp(max_tlp)
        self.file = FileEnricher(
            helper,
            client,
            default_tlp,
            variant_limit=variant_limit,
            sightings_limit=sightings_limit,
            opencti_base_url=opencti_base_url,
        )
        self.domain = DomainEnricher(
            helper, client, default_tlp, resolutions_limit=resolutions_limit
        )
        self.ip = IpEnricher(helper, client, default_tlp)
        self.asn = AsnEnricher(helper, client, default_tlp)

    def _enricher_for(self, observable: dict[str, Any]) -> Any:
        entity_type = (observable.get("entity_type") or "").lower()
        if entity_type in ("stixfile", "file"):
            return self.file
        if entity_type == "domain-name":
            return self.domain
        if entity_type in ("ipv4-addr", "ipv6-addr"):
            return self.ip
        if entity_type == "autonomous-system":
            return self.asn
        return None

    def supports(self, observable: dict[str, Any]) -> bool:
        return self._enricher_for(observable) is not None

    def dispatch(
        self, observable: dict[str, Any], extra_tlps: list[str] | None = None
    ) -> str:
        # Every enricher sends the observable's value to Stairwell, so the
        # gate runs before any of them. `extra_tlps` are the markings on the
        # playbook's copy of the entity, which an earlier step may have
        # raised. A TLP that pycti does not recognise fails the check and is
        # refused.
        for tlp in [*observable_tlps(observable), *(extra_tlps or [])]:
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                raise ValueError(
                    f"Observable is marked {tlp}, above the connector's max TLP "
                    f"{self.max_tlp}; not sent to Stairwell"
                )
        enricher = self._enricher_for(observable)
        if enricher is None:
            entity_type = observable.get("entity_type")
            return f"Unsupported entity_type for Stairwell enrichment: {entity_type!r}"
        return enricher.enrich(observable)
