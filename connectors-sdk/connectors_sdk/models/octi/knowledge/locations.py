"""Offer locations OpenCTI entities."""

from typing import Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from pydantic import Field


class OCTIStixLocation(stix2.Location):  # type: ignore[misc]  # stix2 does not provide stubs
    """Override stix2 Location to skip some constraints incompatible with OpenCTI Location entities."""

    def _check_object_constraints(self) -> None:
        """Override _check_object_constraints method."""
        location_type = (self.x_opencti_location_type or "").lower()
        if location_type in ["administrative-area", "city", "position"]:
            if self.get("precision") is not None:
                self._check_properties_dependency(
                    ["longitude", "latitude"], ["precision"]
                )

            self._check_properties_dependency(["latitude"], ["longitude"])
            self._check_properties_dependency(["longitude"], ["latitude"])

            # Skip region/country/latitude/longitude presence check because all of them are optional on OpenCTI
            # even though at least one of them is required in the STIX2.1 spec
        else:
            super()._check_object_constraints()


@MODEL_REGISTRY.register
class Country(BaseIdentifiedEntity):
    """Represent a Country on OpenCTI."""

    name: str = Field(
        description="A name used to identify the Location.",
    )
    description: Optional[str] = Field(
        None,
        description="A textual description of the Location.",
    )

    def to_stix2_object(self) -> stix2.Location:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Location SDO to OCTI Country entity based on `x_opencti_location_type`.
            - To create a Country entity on OpenCTI, `x_opencti_location_type` MUST be 'Country'.
        """
        location_type = "Country"

        return OCTIStixLocation(
            id=pycti.Location.generate_id(
                name=self.name,
                x_opencti_location_type=location_type,
            ),
            name=self.name,
            country=self.name,
            description=self.description,
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_location_type=location_type,
            ),
            latitude=None,
            longitude=None,
            precision=None,
            region=None,
            administrative_area=None,
            city=None,
            street_address=None,
            postal_code=None,
            created=None,
            modified=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
