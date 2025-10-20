"""Offer OpenCTI entities."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    IndustrySector,
    Reliability,
)
from pycti import Identity as PyctiIdentity
from pydantic import Field
from stix2.v21 import Identity as Stix2Identity


class Sector(BaseIdentifiedEntity):
    """Represents a Sector on OpenCTI."""

    name: str = Field(
        description="Name of the sector.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the sector.",
    )
    sectors: list[IndustrySector] | None = Field(
        default=None,
        description="The list of industry sectors that this Identity belongs to.",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="OpenCTI Reliability of the sector.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Aliases of the sector.",
    )

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Identity SDO to OCTI Sector entity based on `identity_class`.
            - To create a Sector entity on OpenCTI, `identity_class` MUST be 'class'.
        """
        identity_class = "class"

        return Stix2Identity(
            id=PyctiIdentity.generate_id(identity_class=identity_class, name=self.name),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            sectors=self.sectors,
            allow_custom=True,
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
            **self._common_stix2_properties()
        )
