"""Composite mapper that handles campaign to locations, identity, and campaign conversion in one step."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_campaign import (
    GTICampaignToSTIXCampaign,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_identity import (
    GTICampaignToSTIXIdentity,
    IdentityWithTiming,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_location import (
    GTICampaignToSTIXLocation,
    LocationWithTiming,
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
        targeted_locations_with_timing = self._get_targeted_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in targeted_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=campaign.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Campaign '{attributes.name}' targets location '{location.name}'",
            )
            relationships.append(relationship)

        # Create relationships between campaign and source locations
        source_locations_with_timing = self._get_source_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in source_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=campaign.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Campaign '{attributes.name}' originates from location '{location.name}'",
            )
            relationships.append(relationship)

        # Create relationships between campaign and targeted industries
        for identity_with_timing in identities_with_timing:
            identity = identity_with_timing.identity
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=campaign.id,
                target_ref=identity.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=identity_with_timing.first_seen,
                stop_time=identity_with_timing.last_seen,
                description=f"Campaign '{attributes.name}' targets industry '{identity.name}'",
            )
            relationships.append(relationship)

        return relationships

    def _get_targeted_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to targeted regions.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to targeted regions

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_targeted
        ]

    def _get_source_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to source regions.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to source regions

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_source
        ]

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
