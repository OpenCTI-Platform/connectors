"""Convert CTM360 ThreatCover TAXII objects into an OpenCTI-ready STIX list."""

import stix2
from pycti import Identity, MarkingDefinition

_TLP_MAPPING = {
    "clear": stix2.TLP_WHITE,
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


def _amber_strict() -> stix2.MarkingDefinition:
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:AMBER+STRICT",
        },
    )


class ConverterToStix:
    """Attribute and mark the STIX objects pulled from the ThreatCover TAXII feed."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        if tlp_level == "amber+strict":
            self.tlp_marking = _amber_strict()
        else:
            self.tlp_marking = _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)

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

            # Only SDOs (which carry a `created` timestamp) accept `created_by_ref`;
            # SCOs use the OpenCTI custom property instead.
            if "created" in enriched and "created_by_ref" not in enriched:
                enriched["created_by_ref"] = author_id

            results.append(enriched)

        return results
