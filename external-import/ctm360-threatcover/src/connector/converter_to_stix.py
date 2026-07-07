"""Convert CTM360 ThreatCover TAXII objects into an OpenCTI-ready STIX list."""

import stix2
from pycti import Identity, MarkingDefinition

# Standard STIX TLP markings whose ids OpenCTI recognizes as-is.
_TLP_MAPPING = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# STIX object types that must be passed through untouched (markings/identity must
# not be re-attributed, and relationships/extensions carry their own refs).
_PASSTHROUGH_TYPES = {
    "identity",
    "marking-definition",
    "relationship",
    "sighting",
    "extension-definition",
}


def _statement_marking(definition: str) -> stix2.MarkingDefinition:
    # OpenCTI models TLP:CLEAR and TLP:AMBER+STRICT as custom statement markings with
    # their own deterministic ids (not the legacy STIX TLP:WHITE/AMBER). This matches
    # connectors-sdk TLPMarking and the platform's canonical marking shape.
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


def _resolve_tlp_marking(tlp_level: str) -> stix2.MarkingDefinition:
    if tlp_level == "clear":
        return _statement_marking("TLP:CLEAR")
    if tlp_level == "amber+strict":
        return _statement_marking("TLP:AMBER+STRICT")
    return _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)


class ConverterToStix:
    """Attribute and mark the STIX objects pulled from the ThreatCover TAXII feed."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        self.tlp_marking = _resolve_tlp_marking(tlp_level)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(
                name="CTM360 ThreatCover", identity_class="organization"
            ),
            name="CTM360 ThreatCover",
            identity_class="organization",
            description="Threat intelligence imported from CTM360 ThreatCover.",
        )

    def process_objects(self, raw_objects: list) -> list:
        """
        Pass TAXII STIX objects through, applying the configured TLP marking and
        attributing SDOs to the ThreatCover author when those fields are absent.
        """
        results = []
        marking_id = self.tlp_marking["id"]
        author_id = self.author["id"]

        for obj in raw_objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type")
            if not obj_type or not obj.get("id"):
                continue
            if obj_type in _PASSTHROUGH_TYPES:
                results.append(obj)
                continue

            enriched = dict(obj)
            markings = list(enriched.get("object_marking_refs") or [])
            if marking_id not in markings:
                markings.append(marking_id)
            enriched["object_marking_refs"] = markings

            # Only SDOs (which carry a `created` timestamp) are attributed to the
            # ThreatCover author; SCOs are passed through in their native form (no
            # author ref) so OpenCTI keeps them as-is.
            if "created" in enriched and "created_by_ref" not in enriched:
                enriched = dict(enriched, created_by_ref=author_id)

            results.append(enriched)

        return results
