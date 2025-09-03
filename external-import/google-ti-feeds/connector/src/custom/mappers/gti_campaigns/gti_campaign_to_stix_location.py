"""Converts GTI campaign location data to STIX location objects."""

from typing import List, Optional

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
from stix2.v21 import Location  # type: ignore


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

    def to_stix(self) -> List[Location]:
        """Convert GTI campaign location data to STIX location objects.

        Returns:
            List[Location]: List of STIX location objects (countries only).

        """
        result: List[Location] = []

        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            return result

        # Process targeted regions
        targeted_regions = self.campaign.attributes.targeted_regions_hierarchy
        if targeted_regions:
            for target_region_data in targeted_regions:
                location = self._create_country_from_targeted(target_region_data)
                if location:
                    result.append(location)

        # Process source regions
        source_regions = self.campaign.attributes.source_regions_hierarchy
        if source_regions:
            for source_region_data in source_regions:
                location = self._create_country_from_source(source_region_data)
                if location:
                    result.append(location)

        return result

    def _create_country_from_targeted(
        self, region_data: TargetedRegion
    ) -> Optional[Location]:
        """Create a LocationCountry object from targeted region data (countries only).

        Args:
            region_data (TargetedRegion): The targeted region data containing country information.

        Returns:
            Optional[Location]: The STIX LocationCountry object, or None if invalid.

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

        return country.to_stix2_object()

    def _create_country_from_source(
        self, region_data: SourceRegion
    ) -> Optional[Location]:
        """Create a LocationCountry object from source region data (countries only).

        Args:
            region_data (SourceRegion): The source region data containing country information.

        Returns:
            Optional[Location]: The STIX LocationCountry object, or None if invalid.

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

        return country.to_stix2_object()
