"""Composite mapper that handles campaign to locations, identity, and campaign conversion in one step."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_campaign import (
    GTICampaignToSTIXCampaign,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_identity import (
    GTICampaignToSTIXIdentity,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_location import (
    GTICampaignToSTIXLocation,
)
from connector.src.custom.mappers.targeting_mappers import targeting_relationships
from connector.src.custom.mappers.timing_models import (
    IdentityWithTiming,
    LocationWithTiming,
)
from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import (  # type: ignore[import-untyped]
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

    def to_stix(self) -> list[Any]:
        """Convert the GTI campaign to a list of STIX objects (locations, identities, campaign, relationships).

        Returns:
            list of STIX objects in order: [locations..., identities..., campaign, relationships...]

        """
        all_entities = []

        # Create location objects from campaign regions
        location_mapper = GTICampaignToSTIXLocation(
            campaign=self.campaign,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations_with_timing = location_mapper.to_stix_with_timing()
        locations = [item.location for item in locations_with_timing]
        all_entities.extend(locations)

        # Create identity objects from targeted industries
        identity_mapper = GTICampaignToSTIXIdentity(
            campaign=self.campaign,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        identities_with_timing = identity_mapper.to_stix_with_timing()
        identities = [item.identity for item in identities_with_timing]
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
        relationships = self._create_relationships(
            campaign_stix, locations_with_timing, identities_with_timing
        )
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self,
        campaign: Any,
        locations_with_timing: list[LocationWithTiming],
        identities_with_timing: list[IdentityWithTiming],
    ) -> list[Any]:
        """Create relationships between the campaign and other entities.

        Args:
            campaign: The campaign object
            locations_with_timing: list of LocationWithTiming objects containing location and timing data
            identities_with_timing: list of IdentityWithTiming objects containing identity and timing data

        Returns:
            list of relationship objects

        """
        relationships: list[Any] = []

        if not hasattr(self.campaign, "attributes") or not self.campaign.attributes:
            return relationships

        attributes = self.campaign.attributes

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        # Create relationships between campaign and targeted locations
        relationships.extend(
            targeting_relationships(
                campaign,
                locations_with_timing,
                identities_with_timing,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
            )
        )

        return relationships

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
