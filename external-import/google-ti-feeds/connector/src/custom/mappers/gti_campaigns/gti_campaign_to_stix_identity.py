"""Converts GTI campaign data to STIX identity objects."""

from typing import List, Optional

from connector.src.custom.models.gti.gti_campaign_model import (
    GTICampaignData,
    TargetedIndustry,
)
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Identity  # type: ignore


class GTICampaignToSTIXIdentity(BaseMapper):
    """Converts GTI campaign data to STIX identity objects representing targeted industries."""

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ):
        """Initialize the GTICampaignToSTIXIdentity object.

        Args:
            campaign (GTICampaignData): The GTI campaign data to convert.
            organization (OrganizationAuthor): The organization identity object.
            tlp_marking (TLPMarking): The TLP marking definition.

        """
        self.campaign = campaign
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Identity]:
        """Convert the GTI campaign targeted industries to STIX Identity objects.

        Returns:
            List[Identity]: The list of STIX Identity objects representing sectors.

        """
        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            raise ValueError("Invalid campaign attributes")

        targeted_industries = self.campaign.attributes.targeted_industries_tree
        if not targeted_industries:
            return []

        result: List[Identity] = []
        processed_industries = set()  # Track to avoid duplicates

        for industry_data in targeted_industries:
            sector = self._process_industry(industry_data)
            if sector and sector.name not in processed_industries:
                result.append(sector)
                processed_industries.add(sector.name)

        return result

    def _process_industry(self, industry_data: TargetedIndustry) -> Optional[Identity]:
        """Process a targeted industry entry and convert to a sector Identity.

        Args:
            industry_data (TargetedIndustry): The targeted industry data to process.

        Returns:
            Optional[Identity]: The STIX Identity object, or None if no valid industry found.

        """
        # Skip industries without valid names - both industry_group and industry must be empty/whitespace
        industry_group_valid = (
            industry_data.industry_group and industry_data.industry_group.strip()
        )
        industry_valid = industry_data.industry and industry_data.industry.strip()

        if not industry_group_valid and not industry_valid:
            return None

        return self._create_sector(industry_data)

    def _create_sector(self, industry_data: TargetedIndustry) -> Identity:
        """Create a Sector Identity object.

        Args:
            industry_data (TargetedIndustry): The targeted industry data containing industry information.

        Returns:
            Identity: The STIX Identity object representing a sector.

        """
        sector_name = industry_data.industry_group

        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            description=industry_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return sector
