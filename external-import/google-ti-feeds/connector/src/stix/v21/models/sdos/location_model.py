"""The module defines the LocationModel class, which represents a STIX 2.1 Location object."""

from typing import Any, Dict, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.region_ov_enums import RegionOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Location,
    _STIXBase21,
)


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

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = LocationModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            name = data.get("name", None)
            x_opencti_location_type = data.get("custom_properties", {}).get(
                "x_opencti_location_type", None
            )
            latitude = data.get("latitude", None)
            longitude = data.get("longitude", None)

            data["id"] = pycti.Location.generate_id(
                name=name,
                x_opencti_location_type=x_opencti_location_type,
                latitude=latitude,
                longitude=longitude,
            )
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = LocationModel._generate_id(data=data)
        data.pop("id")

        return Location(id=pycti_id, **data)
