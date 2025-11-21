"""Country."""

from connectors_sdk.models._location import Location
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import LocationType
from pycti import Location as PyctiLocation
from pydantic import Field
from stix2.v21 import Location as Stix2Location


class Country(BaseIdentifiedEntity):
    """Represent a Country on OpenCTI."""

    name: str = Field(
        description="A name used to identify the Country.",
    )
    description: str | None = Field(
        default=None,
        description="A textual description of the Country.",
    )

    def to_stix2_object(self) -> Stix2Location:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Location SDO to OCTI Country entity based on `x_opencti_location_type`.
            - To create a Country entity on OpenCTI, `x_opencti_location_type` MUST be 'Country'.
        """
        location_type = LocationType.COUNTRY.value

        return Location(
            id=PyctiLocation.generate_id(
                name=self.name,
                x_opencti_location_type=location_type,
            ),
            name=self.name,
            country=self.name,
            description=self.description,
            allow_custom=True,
            x_opencti_location_type=location_type,
            **self._common_stix2_properties()
        )
