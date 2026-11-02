from __future__ import annotations

from typing import Any

from connector.asn_enricher import AsnEnricher
from connector.domain_enricher import DomainEnricher
from connector.file_enricher import FileEnricher
from connector.ip_enricher import IpEnricher
from connector.stairwell import StairwellClient
from connector.stix_builder import TLP_IDS
from connectors_sdk.exceptions.error import UseCaseError
from pycti import OpenCTIConnectorHelper


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
    known_markings: list[dict[str, Any]] | None = None,
) -> tuple[list[str], list[str]]:
    """TLP levels of a STIX object's `object_marking_refs`, and the refs that
    could not be resolved.

    A ref resolves through the standard TLP marking IDs, a marking-definition
    object in `objects`, or `known_markings` (the stored entity's
    `objectMarking`, matched by `standard_id`). A marking of another kind,
    such as PAP, is not a TLP restriction. A ref that cannot be resolved
    yields `UNRESOLVED_MARKING`, which the gate refuses: it could be a RED
    marking.
    """
    definitions = {
        o.get("id"): o
        for o in objects
        if isinstance(o, dict) and o.get("type") == "marking-definition"
    }
    for marking in known_markings or []:
        if isinstance(marking, dict) and marking.get("standard_id"):
            definitions.setdefault(marking["standard_id"], marking)
    levels: list[str] = []
    unresolved: list[str] = []
    for ref in entity.get("object_marking_refs") or []:
        if ref in _TLP_BY_MARKING_ID:
            levels.append(_TLP_BY_MARKING_ID[ref])
            continue
        level = _marking_tlp(definitions[ref]) if ref in definitions else None
        if level is None:
            unresolved.append(ref)
            levels.append(UNRESOLVED_MARKING)
        elif level:
            levels.append(level)
    return levels, unresolved


class Dispatcher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        *,
        variant_limit: int,
        resolutions_limit: int,
        sightings_limit: int,
        opencti_base_url: str,
        max_tlp: str,
    ) -> None:
        """`max_tlp` is a canonical `TLP:*` level, as pycti's
        `check_max_tlp` expects."""
        self.helper = helper
        self.max_tlp = max_tlp
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
                raise UseCaseError(
                    f"Observable is marked {tlp}, above the connector's max TLP "
                    f"{self.max_tlp}; not sent to Stairwell"
                )
        enricher = self._enricher_for(observable)
        if enricher is None:
            entity_type = observable.get("entity_type")
            return f"Unsupported entity_type for Stairwell enrichment: {entity_type!r}"
        return enricher.enrich(observable)
