"""The module defines the LocationModel class, which represents a STIX 2.1 Location object."""

from typing import Optional

from connector.src.stix.v21.models.ovs.region_ov_enums import RegionOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import Location, _STIXBase21  # type: ignore


class LocationModel(BaseSDOModel):
    """Model representing a Location in STIX 2.1 format."""

    name: Optional[str] = Field(
        default=None, description="A name used to identify the Location."
    )
    description: Optional[str] = Field(
        default=None, description="A textual description of the Location."
    )

    latitude: Optional[float] = Field(
        default=None,
        description="Latitude in decimal degrees. Must be between -90.0 and 90.0. Required if longitude is present.",
        ge=-90.0,
        le=90.0,
    )
    longitude: Optional[float] = Field(
        default=None,
        description="Longitude in decimal degrees. Must be between -180.0 and 180.0. Required if latitude is present.",
        ge=-180.0,
        le=180.0,
    )
    precision: Optional[float] = Field(
        default=None,
        description="Precision in meters. If present, latitude and longitude MUST also be present.",
    )

    region: Optional[RegionOV] = Field(
        default=None, description="Region for this location (from region-ov)."
    )
    country: Optional[str] = Field(
        default=None, description="Country code in ISO 3166-1 ALPHA-2 format."
    )
    administrative_area: Optional[str] = Field(
        default=None, description="Sub-national area (state, province, etc)."
    )
    city: Optional[str] = Field(
        default=None, description="The city that this Location describes."
    )
    street_address: Optional[str] = Field(
        default=None, description="The full street address for the Location."
    )
    postal_code: Optional[str] = Field(
        default=None, description="Postal code for the Location."
    )

    @model_validator(mode="after")
    def validate_coordinates(self, model):  # type: ignore
        """Ensure that latitude and longitude are provided together."""
        lat = model.latitude
        lon = model.longitude
        prec = model.precision

        if (lat is None) ^ (lon is None):
            raise ValueError(
                "Both 'latitude' and 'longitude' must be provided together."
            )
        if prec is not None and (lat is None or lon is None):
            raise ValueError(
                "'precision' requires both 'latitude' and 'longitude' to be set."
            )

        return model

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Location(**self.model_dump(exclude_none=True))


def test_location_model() -> None:
    """Test function to demonstrate the usage of LocationModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    # === Minimal Location ===
    minimal = LocationModel(
        type="location",
        spec_version="2.1",
        id=f"location--{uuid4()}",
        region=RegionOV.EASTERN_ASIA,
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
    )

    print("=== MINIMAL LOCATION ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Location ===
    full = LocationModel(
        type="location",
        spec_version="2.1",
        id=f"location--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        name="Tokyo SOC",
        description="Primary security operations center located in central Tokyo.",
        latitude=35.6895,
        longitude=139.6917,
        precision=50.0,
        region=RegionOV.EASTERN_ASIA,
        country="JP",
        administrative_area="Tokyo Metropolis",
        city="Tokyo",
        street_address="1-1 Chiyoda",
        postal_code="100-0001",
        labels=["physical-location", "sensitive"],
        confidence=85,
        lang="ja",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description", "latitude", "longitude"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "zone_type": "restricted",
            }
        },
    )

    print("\n=== FULL LOCATION ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_location_model()
