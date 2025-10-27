"""City."""

from connectors_sdk.models._location import Location
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import LocationType
from pycti import Location as PyctiLocation
from pydantic import Field
from stix2.v21 import Location as Stix2Location


class City(BaseIdentifiedEntity):
    """Represent a city entity."""

    name: str = Field(
        description="A name used to identify the City.",
    )
    description: str | None = Field(
        default=None,
        description="A textual description of the City.",
    )
    latitude: float | None = Field(
        default=None,
        description="The latitude of the City in decimal degrees.",
    )
    longitude: float | None = Field(
        default=None,
        description="The longitude of the City in decimal degrees.",
    )

    def to_stix2_object(self) -> Stix2Location:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Location SDO to OCTI City entity based on `x_opencti_location_type`.
            - To create a City entity on OpenCTI, `x_opencti_location_type` MUST be 'City'.
        """
        location_type = LocationType.CITY.value

        return Location(
            id=PyctiLocation.generate_id(
                name=self.name,
                x_opencti_location_type=location_type,
                latitude=self.latitude,
                longitude=self.longitude,
            ),
            name=self.name,
            city=self.name,
            description=self.description,
            latitude=self.latitude,
            longitude=self.longitude,
            allow_custom=True,
            x_opencti_location_type=location_type,
            **self._common_stix2_properties()
        )
