"""Converts GTI campaign location data to STIX location objects."""

from datetime import datetime, timezone

from connector.src.custom.models.gti.gti_campaign_model import (
    GTICampaignData,
    SourceRegion,
    TargetedRegion,
)
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from pydantic import BaseModel
from stix2.v21 import Location  # type: ignore


class LocationWithTiming(BaseModel):
    """Container for a STIX Location object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    location: Location
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_targeted: bool = False
    is_source: bool = False


class GTICampaignToSTIXLocation(BaseMapper):
    """Converts GTI campaign location data to STIX location objects (countries only)."""

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTICampaignToSTIXLocation object.

        Args:
            campaign (GTICampaignData): The GTI campaign data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.campaign = campaign
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> list[Location]:
        """Convert GTI campaign location data to STIX location objects.

        Returns:
            list[Location]: list of STIX location objects (countries only).

        """
        return [item.location for item in self.to_stix_with_timing()]

    def to_stix_with_timing(self) -> list[LocationWithTiming]:
        """Convert the GTI campaign location data to LocationWithTiming objects.

        Returns:
            list[LocationWithTiming]: The list of LocationWithTiming objects containing STIX Location objects and timing metadata.

        """
        result: list[LocationWithTiming] = []

        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            return result

        # Process targeted regions
        targeted_regions = self.campaign.attributes.targeted_regions_hierarchy
        if targeted_regions:
            for target_region_data in targeted_regions:
                location_with_timing = self._create_country_from_targeted_with_timing(
                    target_region_data
                )
                if location_with_timing:
                    result.append(location_with_timing)

        # Process source regions
        source_regions = self.campaign.attributes.source_regions_hierarchy
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
            # If stop_time is not later than start_time, only keep start_time
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
            region_data (TargetedRegion): The targeted region data containing country information.

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
            region_data (SourceRegion): The source region data containing country information.

        Returns:
            LocationWithTiming | None: The LocationWithTiming object with timing metadata, or None if invalid.

        """
        return self._create_country_with_timing(
            region_data=region_data,
            is_targeted=False,
            is_source=True,
        )
