"""Converts a GTI software toolkit's country regions to STIX Location objects."""

from datetime import datetime, timezone

from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
    SourceRegion,
    TargetedRegion,
)
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import (
    OrganizationAuthor,
    TLPMarking,
)
from pydantic import BaseModel
from stix2.v21 import Location


class LocationWithTiming(BaseModel):
    """Container for a STIX Location object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    location: Location
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_targeted: bool = False
    is_source: bool = False


class GTISoftwareToolkitToSTIXLocation(BaseMapper):
    """Converts a GTI Software Toolkit's country regions to STIX Location objects."""

    def __init__(
        self,
        software_toolkit: GTISoftwareToolkitData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ):
        """Initialize the GTISoftwareToolkitToSTIXLocation object.

        Args:
            software_toolkit: The GTI software toolkit data to convert.
            organization: The organization identity object.
            tlp_marking: The TLP marking definition.

        """
        self.software_toolkit = software_toolkit
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> list[Location]:
        """Convert the GTI software toolkit country regions to STIX Location objects.

        Returns:
            list[Location]: The list of STIX Location objects (countries only).

        """
        return [item.location for item in self.to_stix_with_timing()]

    def to_stix_with_timing(self) -> list[LocationWithTiming]:
        """Convert the GTI software toolkit country regions to LocationWithTiming objects.

        Returns:
            list[LocationWithTiming]: The list of LocationWithTiming objects containing STIX Location objects and timing metadata.

        """
        result: list[LocationWithTiming] = []

        if (
            not hasattr(self.software_toolkit, "attributes")
            or not self.software_toolkit.attributes
        ):
            raise ValueError("Invalid software toolkit attributes")

        targeted_regions = self.software_toolkit.attributes.targeted_regions_hierarchy
        if targeted_regions:
            for target_region_data in targeted_regions:
                location_with_timing = self._create_country_from_targeted_with_timing(
                    target_region_data
                )
                if location_with_timing:
                    result.append(location_with_timing)

        source_regions = self.software_toolkit.attributes.source_regions_hierarchy
        if source_regions:
            for source_region_data in source_regions:
                location_with_timing = self._create_country_from_source_with_timing(
                    source_region_data
                )
                if location_with_timing:
                    result.append(location_with_timing)

        return result

    def _create_country_with_timing(
        self, region_data, is_targeted: bool, is_source: bool
    ) -> LocationWithTiming | None:
        """Create a LocationWithTiming object from region data (countries only).

        Args:
            region_data: The region data containing country information.
            is_targeted: Whether this is a targeted region.
            is_source: Whether this is a source region.

        Returns:
            LocationWithTiming | None: The LocationWithTiming object with timing metadata, or None if invalid.

        """
        if not region_data.country or not region_data.country_iso2:
            return None

        country = OctiLocationModel.create_country(
            name=region_data.country,
            country_code=region_data.country_iso2,
            description=region_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        first_seen = None
        if region_data.first_seen:
            first_seen = datetime.fromtimestamp(region_data.first_seen, tz=timezone.utc)

        last_seen = None
        if region_data.last_seen:
            last_seen = datetime.fromtimestamp(region_data.last_seen, tz=timezone.utc)

        # Validate timing: if both are present, stop_time must be later than start_time
        if first_seen and last_seen and last_seen <= first_seen:
            last_seen = None

        return LocationWithTiming(
            location=country.to_stix2_object(),
            first_seen=first_seen,
            last_seen=last_seen,
            is_targeted=is_targeted,
            is_source=is_source,
        )

    def _create_country_from_targeted_with_timing(
        self, region_data: TargetedRegion
    ) -> LocationWithTiming | None:
        """Create a LocationWithTiming object from targeted region data (countries only).

        Args:
            region_data: The targeted region data containing country information.

        Returns:
            LocationWithTiming | None: The LocationWithTiming object with timing metadata, or None if invalid.

        """
        return self._create_country_with_timing(
            region_data=region_data,
            is_targeted=True,
            is_source=False,
        )

    def _create_country_from_source_with_timing(
        self, region_data: SourceRegion
    ) -> LocationWithTiming | None:
        """Create a LocationWithTiming object from source region data (countries only).

        Args:
            region_data: The source region data containing country information.

        Returns:
            LocationWithTiming | None: The LocationWithTiming object with timing metadata, or None if invalid.

        """
        return self._create_country_with_timing(
            region_data=region_data,
            is_targeted=False,
            is_source=True,
        )
