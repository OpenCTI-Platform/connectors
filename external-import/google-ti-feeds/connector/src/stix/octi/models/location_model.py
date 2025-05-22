"""The module contains the OctiLocationModel class, which represents an OpenCTI Location."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from connector.src.stix.v21.models.ovs.region_ov_enums import RegionOV
from connector.src.stix.v21.models.sdos.location_model import LocationModel


class OctiLocationModel:
    """Model for creating OpenCTI Location objects."""

    @staticmethod
    def create_country(
        name: str,
        country_code: str,
        organization_id: str,
        marking_ids: List[str],
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> LocationModel:
        """Create a Country Location model with OpenCTI custom properties.

        Args:
            name: The name of the country
            country_code: The ISO 3166-1 alpha-2 country code
            organization_id: The ID of the organization that created this location
            marking_ids: List of marking definition IDs to apply to the location
            description: Description of the location
            **kwargs: Additional arguments to pass to LocationModel

        Returns:
            LocationModel: The created location model

        """
        custom_properties: Dict[str, Any] = kwargs.pop("custom_properties", {})
        custom_properties["x_opencti_location_type"] = "Country"

        data = {
            "type": "location",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "country": country_code,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return LocationModel(**data)

    @staticmethod
    def create_region(
        name: str,
        region_value: RegionOV,
        organization_id: str,
        marking_ids: List[str],
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> LocationModel:
        """Create a Region Location model with OpenCTI custom properties.

        Args:
            name: The name of the region
            region_value: The region value from RegionOV enum
            organization_id: The ID of the organization that created this location
            marking_ids: List of marking definition IDs to apply to the location
            description: Description of the location
            **kwargs: Additional arguments to pass to LocationModel

        Returns:
            LocationModel: The created location model

        """
        custom_properties: Dict[str, Any] = kwargs.pop("custom_properties", {})
        custom_properties["x_opencti_location_type"] = "Region"

        data = {
            "type": "location",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "region": region_value,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            "custom_properties": custom_properties,
            **kwargs,
        }

        return LocationModel(**data)
