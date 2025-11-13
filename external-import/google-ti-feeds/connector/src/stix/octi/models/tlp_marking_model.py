"""The module defines the MarkingDefinitionModel class, which represents a marking definition in STIX 2.1 format."""

from typing import Literal

import pycti  # type: ignore  # Missing library stubs
import stix2  # type: ignore[import-untyped]  # Missing library stubs
from pydantic import BaseModel, Field


class TLPMarkingModel(BaseModel):
    """Model representing a marking definition in STIX 2.1 format."""

    level: Literal["white", "green", "amber", "amber+strict", "red"] = Field(
        ...,
        description="The level of the marking.",
    )

    def to_stix2_object(self) -> stix2.v21.MarkingDefinition:
        """Make stix object."""
        mapping = {
            "white": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties=dict(  # noqa: C408
                    x_opencti_definition_type="TLP",
                    x_opencti_definition="TLP:AMBER+STRICT",
                ),
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[self.level]
