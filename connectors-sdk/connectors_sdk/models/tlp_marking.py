"""TLPMarking."""

from connectors_sdk.models._base_identified_entity import _BaseIdentifiedEntity
from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.octi.enums import TLPLevel
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pydantic import Field
from stix2.v21 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.v21 import MarkingDefinition as Stix2MarkingDefinition


@MODEL_REGISTRY.register
class TLPMarking(_BaseIdentifiedEntity):
    """Represent a TLP marking definition."""

    level: TLPLevel = Field(description="The level of the TLP marking.")

    def to_stix2_object(self) -> Stix2MarkingDefinition:
        """Make stix object."""
        mapping = {
            "clear": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            ),
            "white": TLP_WHITE,
            "green": TLP_GREEN,
            "amber": TLP_AMBER,
            "amber+strict": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "red": TLP_RED,
        }
        return mapping[self.level]
