"""TLPMarking."""

from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.enums import TLPLevel
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pydantic import Field
from stix2.v21 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.v21 import MarkingDefinition as Stix2MarkingDefinition


class TLPMarking(BaseIdentifiedObject):
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
