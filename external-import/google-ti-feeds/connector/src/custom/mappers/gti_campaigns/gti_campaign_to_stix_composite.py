"""Composite mapper that handles campaign to locations, identity, and campaign conversion in one step."""

from datetime import datetime, timezone
from typing import Any, List

from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_campaign import (
    GTICampaignToSTIXCampaign,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_identity import (
    GTICampaignToSTIXIdentity,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_location import (
    GTICampaignToSTIXLocation,
)
from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTICampaignToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI campaign to locations, identity, and campaign STIX objects."""

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            campaign: The GTI campaign data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition

        """
        self.campaign = campaign
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Any]:
        """Convert the GTI campaign to a list of STIX objects (locations, identities, campaign, relationships).

        Returns:
            List of STIX objects in order: [locations..., identities..., campaign, relationships...]

        """
        all_entities = []

        # Create location objects from campaign regions
        location_mapper = GTICampaignToSTIXLocation(
            campaign=self.campaign,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations = location_mapper.to_stix()
        all_entities.extend(locations)

        # Create identity objects from targeted industries
        identity_mapper = GTICampaignToSTIXIdentity(
            campaign=self.campaign,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        identities = identity_mapper.to_stix()
        all_entities.extend(identities)

        # Create the main campaign object
        campaign_mapper = GTICampaignToSTIXCampaign(
            campaign=self.campaign,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        campaign_stix = campaign_mapper.to_stix()
        all_entities.append(campaign_stix)

        # Create relationships between campaign and other entities
        relationships = self._create_relationships(campaign_stix, locations, identities)
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self, campaign: Any, locations: List[Any], identities: List[Any]
    ) -> List[Any]:
        """Create relationships between the campaign and other entities.

        Args:
            campaign: The campaign object
            locations: List of location objects
            identities: List of identity objects

        Returns:
            List of relationship objects

        """
        relationships: List[Any] = []

        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            return relationships

        attributes = self.campaign.attributes

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        # Create relationships between campaign and targeted locations
        targeted_locations = self._get_targeted_locations(locations)
        for location in targeted_locations:
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=campaign.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Campaign '{attributes.name}' targets location '{location.name}'",
            )
            relationships.append(relationship)

        # Create relationships between campaign and source locations
        source_locations = self._get_source_locations(locations)
        for location in source_locations:
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=campaign.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Campaign '{attributes.name}' originates from location '{location.name}'",
            )
            relationships.append(relationship)

        # Create relationships between campaign and targeted industries
        for identity in identities:
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=campaign.id,
                target_ref=identity.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Campaign '{attributes.name}' targets industry '{identity.name}'",
            )
            relationships.append(relationship)

        return relationships

    def _get_targeted_locations(self, locations: List[Any]) -> List[Any]:
        """Get locations that correspond to targeted regions.

        Args:
            locations: List of all location objects

        Returns:
            List of location objects that correspond to targeted regions

        """
        targeted_locations: List[Any] = []

        if (
            not self.campaign.attributes
            or not self.campaign.attributes.targeted_regions_hierarchy
        ):
            return targeted_locations

        targeted_country_names = set()
        for region in self.campaign.attributes.targeted_regions_hierarchy:
            if region.country:
                targeted_country_names.add(region.country.lower())

        for location in locations:
            if hasattr(location, "name") and location.name:
                if location.name.lower() in targeted_country_names:
                    targeted_locations.append(location)

        return targeted_locations

    def _get_source_locations(self, locations: List[Any]) -> List[Any]:
        """Get locations that correspond to source regions.

        Args:
            locations: List of all location objects

        Returns:
            List of location objects that correspond to source regions

        """
        source_locations: List[Any] = []

        if (
            not self.campaign.attributes
            or not self.campaign.attributes.source_regions_hierarchy
        ):
            return source_locations

        source_country_names = set()
        for region in self.campaign.attributes.source_regions_hierarchy:
            if region.country:
                source_country_names.add(region.country.lower())

        for location in locations:
            if hasattr(location, "name") and location.name:
                if location.name.lower() in source_country_names:
                    source_locations.append(location)

        return source_locations

    @staticmethod
    def create_relationship(source: Any, rel_type: str, target: Any) -> Any:
        """Create a STIX relationship between two entities.

        Args:
            source: Source STIX entity
            rel_type: Relationship type (e.g., 'uses', 'targets', 'related-to')
            target: Target STIX entity

        Returns:
            STIX relationship object

        """
        return GTICampaignToSTIXCampaign.create_relationship(source, rel_type, target)
