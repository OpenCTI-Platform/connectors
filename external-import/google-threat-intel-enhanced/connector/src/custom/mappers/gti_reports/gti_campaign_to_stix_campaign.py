"""Converts a GTI campaign to a STIX campaign object."""

from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from connector.src.custom.models.gti_reports.gti_campaign_model import (
    CampaignModel,
    GTICampaignData,
    SourceRegion,
    TargetedIndustry,
    TargetedRegion,
)
from connector.src.stix.octi.models.campaign_model import OctiCampaignModel
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Campaign, Identity, MarkingDefinition  # type: ignore


class GTICampaignToSTIXCampaign(BaseMapper):
    """Converts a GTI campaign to a STIX campaign object."""

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        **kwargs: Any,
    ) -> None:
        """Initialize the GTICampaignToSTIXCampaign object.

        Args:
            campaign (GTICampaignData): The GTI campaign data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.campaign = campaign
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Any]:
        """Convert the GTI campaign to a STIX campaign object.

        Returns:
            List[Any]: The STIX campaign and related objects (locations, sectors, relationships).

        """
        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            raise ValueError("Invalid GTI campaign data")

        attributes = self.campaign.attributes

        name = attributes.name
        if len(name) < 2:
            raise ValueError("Campaign name must be at least 2 characters long")

        # Extract timestamps with fallback to current time
        now = datetime.now(tz=timezone.utc)
        created = now
        modified = now
        if attributes.creation_date:
            created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        if attributes.last_modification_date:
            modified = datetime.fromtimestamp(
                attributes.last_modification_date, tz=timezone.utc
            )

        first_seen, last_seen = self._get_activity_timestamps(attributes)
        aliases = self._extract_aliases(attributes)
        labels = self._extract_labels(attributes)
        external_references = self._build_external_references(attributes)

        campaign_model = OctiCampaignModel.create(
            name=name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=attributes.description,
            created=created,
            modified=modified,
            first_seen=first_seen,
            last_seen=last_seen,
            aliases=aliases,
            labels=labels,
            external_references=[
                ref.model_dump(exclude_none=True) for ref in external_references
            ] if external_references else None,
        )

        # Build result list with campaign and related objects
        result: List[Any] = [campaign_model]

        # Extract source locations (originates-from relationships)
        source_objects = self._extract_source_locations(
            campaign_model, attributes, created, modified
        )
        result.extend(source_objects)

        # Extract targeted sectors (targets relationships)
        sector_objects = self._extract_targeted_sectors(
            campaign_model, attributes, created, modified
        )
        result.extend(sector_objects)

        # Extract targeted regions (targets relationships)
        region_objects = self._extract_targeted_regions(
            campaign_model, attributes, created, modified
        )
        result.extend(region_objects)

        return result

    @staticmethod
    def _get_activity_timestamps(
        attributes: CampaignModel,
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """Extract first and last seen timestamps from attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            tuple: (first_seen, last_seen) datetime objects or None

        """
        first_seen = None
        last_seen = None

        # Extract from first_seen_details
        if attributes.first_seen_details:
            for detail in attributes.first_seen_details:
                if detail.value:
                    try:
                        first_seen = datetime.fromisoformat(
                            detail.value.replace("Z", "+00:00")
                        )
                        break
                    except (ValueError, AttributeError):
                        continue

        # Extract from last_seen_details
        if attributes.last_seen_details:
            for detail in attributes.last_seen_details:
                if detail.value:
                    try:
                        last_seen = datetime.fromisoformat(
                            detail.value.replace("Z", "+00:00")
                        )
                        break
                    except (ValueError, AttributeError):
                        continue

        return first_seen, last_seen

    @staticmethod
    def _extract_aliases(attributes: CampaignModel) -> Optional[List[str]]:
        """Extract aliases from campaign attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            Optional[List[str]]: Extracted aliases or None if no aliases exist

        """
        if not attributes.alt_names_details:
            return None

        aliases = []
        for alt_name in attributes.alt_names_details:
            if alt_name.value and alt_name.value not in aliases:
                aliases.append(alt_name.value)

        return aliases if aliases else None

    @staticmethod
    def _extract_labels(attributes: CampaignModel) -> Optional[List[str]]:
        """Extract labels from campaign attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            Optional[List[str]]: Extracted labels or None

        """
        labels = []
        if attributes.tags_details:
            for tag in attributes.tags_details:
                if tag.value and tag.value not in labels:
                    labels.append(tag.value)
        return labels if labels else None

    def _build_external_references(
        self, attributes: CampaignModel
    ) -> List[ExternalReferenceModel]:
        """Build external references from campaign attributes.

        Args:
            attributes: The campaign attributes

        Returns:
            list: External references

        """
        external_references = []

        # Add GTI campaign reference
        if self.campaign.id and attributes.name:
            external_reference = ExternalReferenceModel(
                source_name=f"[GTI] Campaign {attributes.name}",
                description="Google Threat Intelligence Campaign Link",
                url=f"https://www.virustotal.com/gui/collection/{self.campaign.id}",
            )
            external_references.append(external_reference)

        return external_references

    def _extract_source_locations(
        self,
        campaign: Campaign,
        attributes: CampaignModel,
        created: Optional[datetime],
        modified: Optional[datetime],
    ) -> List[Any]:
        """Extract source locations from campaign attributes.

        Args:
            campaign: The STIX campaign object
            attributes: The campaign attributes
            created: Creation timestamp
            modified: Modification timestamp

        Returns:
            List[Any]: Location objects and originates-from relationships

        """
        result: List[Any] = []
        if not attributes.source_regions_hierarchy:
            return result

        seen_source_countries: set = set()
        for source_region in attributes.source_regions_hierarchy:
            objects = self._create_source_location(
                campaign, source_region, created, modified, seen_source_countries
            )
            result.extend(objects)

        return result

    def _create_source_location(
        self,
        campaign: Campaign,
        source_region: SourceRegion,
        created: Optional[datetime],
        modified: Optional[datetime],
        seen_source_countries: set,
    ) -> List[Any]:
        """Create a source location and originates-from relationship.

        Args:
            campaign: The STIX campaign object
            source_region: The source region data
            created: Creation timestamp
            modified: Modification timestamp
            seen_source_countries: Set of already processed country codes to avoid duplicates

        Returns:
            List[Any]: Location and relationship objects

        """
        result: List[Any] = []

        # Check for country in the hierarchy
        if not source_region.country or not source_region.country_iso2:
            return result

        # Avoid duplicates within this campaign
        if source_region.country_iso2 in seen_source_countries:
            return result
        seen_source_countries.add(source_region.country_iso2)

        # Create location object
        location = OctiLocationModel.create_country(
            name=source_region.country,
            country_code=source_region.country_iso2,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(location)

        # Create originates-from relationship
        relationship = RelationshipModel(
            relationship_type="originates-from",
            source_ref=campaign.id,
            target_ref=location.id,
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(relationship)

        return result

    def _extract_targeted_sectors(
        self,
        campaign: Campaign,
        attributes: CampaignModel,
        created: Optional[datetime],
        modified: Optional[datetime],
    ) -> List[Any]:
        """Extract targeted sectors from campaign attributes.

        Args:
            campaign: The STIX campaign object
            attributes: The campaign attributes
            created: Creation timestamp
            modified: Modification timestamp

        Returns:
            List[Any]: Sector identity objects and targets relationships

        """
        result: List[Any] = []
        if not attributes.targeted_industries_tree:
            return result

        seen_sectors: set = set()
        for industry in attributes.targeted_industries_tree:
            objects = self._create_targeted_sector(
                campaign, industry, created, modified, seen_sectors
            )
            result.extend(objects)

        return result

    def _create_targeted_sector(
        self,
        campaign: Campaign,
        industry: TargetedIndustry,
        created: Optional[datetime],
        modified: Optional[datetime],
        seen_sectors: set,
    ) -> List[Any]:
        """Create a targeted sector and targets relationship.

        Args:
            campaign: The STIX campaign object
            industry: The targeted industry data
            created: Creation timestamp
            modified: Modification timestamp
            seen_sectors: Set of already processed sector names to avoid duplicates

        Returns:
            List[Any]: Sector identity and relationship objects

        """
        result: List[Any] = []

        # Use industry_group as the sector name (industry is optional sub-industry)
        sector_name = industry.industry_group or industry.industry
        if not sector_name:
            return result

        # Avoid duplicates within this campaign
        if sector_name in seen_sectors:
            return result
        seen_sectors.add(sector_name)

        # Create sector identity
        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(sector)

        # Create targets relationship
        relationship = RelationshipModel(
            relationship_type="targets",
            source_ref=campaign.id,
            target_ref=sector.id,
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(relationship)

        return result

    def _extract_targeted_regions(
        self,
        campaign: Campaign,
        attributes: CampaignModel,
        created: Optional[datetime],
        modified: Optional[datetime],
    ) -> List[Any]:
        """Extract targeted regions from campaign attributes.

        Args:
            campaign: The STIX campaign object
            attributes: The campaign attributes
            created: Creation timestamp
            modified: Modification timestamp

        Returns:
            List[Any]: Location objects and targets relationships

        """
        result: List[Any] = []
        if not attributes.targeted_regions_hierarchy:
            return result

        seen_countries: set = set()
        for region in attributes.targeted_regions_hierarchy:
            objects = self._create_targeted_location(
                campaign, region, created, modified, seen_countries
            )
            result.extend(objects)

        return result

    def _create_targeted_location(
        self,
        campaign: Campaign,
        region: TargetedRegion,
        created: Optional[datetime],
        modified: Optional[datetime],
        seen_countries: set,
    ) -> List[Any]:
        """Create a targeted location and targets relationship.

        Args:
            campaign: The STIX campaign object
            region: The targeted region data
            created: Creation timestamp
            modified: Modification timestamp
            seen_countries: Set of already processed country codes to avoid duplicates

        Returns:
            List[Any]: Location and relationship objects

        """
        result: List[Any] = []

        # Check for country in the hierarchy
        if not region.country or not region.country_iso2:
            return result

        # Avoid duplicates within this campaign
        if region.country_iso2 in seen_countries:
            return result
        seen_countries.add(region.country_iso2)

        # Create location object
        location = OctiLocationModel.create_country(
            name=region.country,
            country_code=region.country_iso2,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(location)

        # Create targets relationship
        relationship = RelationshipModel(
            relationship_type="targets",
            source_ref=campaign.id,
            target_ref=location.id,
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
            created=created,
            modified=modified,
        )
        result.append(relationship)

        return result
