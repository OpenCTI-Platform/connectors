"""Region."""

from connectors_sdk.models import BaseIdentifiedEntity
from connectors_sdk.models._location import Location
from connectors_sdk.models.enums import (
    ExtensionDefinitionId,
    ExtensionType,
    LocationType,
)
from pycti import Location as PyctiLocation
from pydantic import Field
from stix2.v21 import Location as Stix2Location


class Region(BaseIdentifiedEntity):
    """Represent a region entity.

    Notes:
        - OpenCTI maps STIX Location SDO to OCTI Region entity based on `x_opencti_location_type`.
        - To create a Region entity on OpenCTI, `x_opencti_location_type` MUST be 'Region'.
    """

    name: str = Field(
        description="A name used to identify the Region.",
    )
    description: str | None = Field(
        default=None,
        description="A textual description of the Region.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Region.",
    )

    def to_stix2_object(self) -> Stix2Location:
        """Make stix object."""
        location_type = LocationType.REGION.value

        custom_properties = {
            "location_type": location_type,
            "aliases": self.aliases,
        }

        return Location(
            id=PyctiLocation.generate_id(
                name=self.name,
                x_opencti_location_type=location_type,
            ),
            name=self.name,
            region=self.name,
            description=self.description,
            allow_custom=True,
            **self._merge_stix2_properties(
                self._common_stix2_properties(),
                self._custom_stix2_extensions(
                    ExtensionDefinitionId.OCTI,
                    extension_type=ExtensionType.PROPERTY_EXTENSION,
                    properties=custom_properties,
                ),
                self._deprecated_x_opencti_properties(custom_properties),
            ),
        )
