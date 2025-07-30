"""Offer locations OpenCTI entities."""

from typing import Optional

from pycti import (  # type: ignore[import-untyped]  # pycti does not provide stubs
    Location as pycti_Location,
)
from pydantic import Field
from stix2 import (  # type: ignore[import-untyped]  # stix2 does not provide stubs
    Location as stix2_Location,
)

from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import LocationType


class OCTIStixLocation(stix2_Location):  # type: ignore[misc]  # stix2 does not provide stubs
    """Override stix2 Location to skip some constraints incompatible with OpenCTI Location entities."""

    def _check_object_constraints(self) -> None:
        """Override _check_object_constraints method."""
        location_type = (self.x_opencti_location_type or "").lower()
        if location_type in ["administrative-area", "city", "position"]:
            self._check_properties_dependency(["latitude"], ["longitude"])
            self._check_properties_dependency(["longitude"], ["latitude"])

            # Skip (region OR country OR (latitude AND longitude)) check because all of them are optional on OpenCTI
            # even though at least one of them is required in the STIX2.1 Location spec
            #
            # Skip (precision AND (latitude OR longitude)) check because OpenCTI does not handle precision at all
        else:
            super()._check_object_constraints()


@MODEL_REGISTRY.register
class City(BaseIdentifiedEntity):
    """Represent a city entity."""

    name: str = Field(
        description="A name used to identify the City.",
    )
    description: Optional[str] = Field(
        description="A textual description of the City.",
        default=None,
    )
    latitude: Optional[float] = Field(
        description="The latitude of the City in decimal degrees.",
        default=None,
    )
    longitude: Optional[float] = Field(
        description="The longitude of the City in decimal degrees.",
        default=None,
    )

    def to_stix2_object(self) -> stix2_Location:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Location SDO to OCTI City entity based on `x_opencti_location_type`.
            - To create a City entity on OpenCTI, `x_opencti_location_type` MUST be 'City'.
        """
        location_type = LocationType.CITY.value

        return OCTIStixLocation(
            id=pycti_Location.generate_id(
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
        )


@MODEL_REGISTRY.register
class Country(BaseIdentifiedEntity):
    """Represent a Country on OpenCTI."""

    name: str = Field(
        description="A name used to identify the Country.",
    )
    description: Optional[str] = Field(
        description="A textual description of the Country.",
        default=None,
    )

    def to_stix2_object(self) -> stix2_Location:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Location SDO to OCTI Country entity based on `x_opencti_location_type`.
            - To create a Country entity on OpenCTI, `x_opencti_location_type` MUST be 'Country'.
        """
        location_type = LocationType.COUNTRY.value

        return OCTIStixLocation(
            id=pycti_Location.generate_id(
                name=self.name,
                x_opencti_location_type=location_type,
            ),
            name=self.name,
            country=self.name,
            description=self.description,
            allow_custom=True,
            x_opencti_location_type=location_type,
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
