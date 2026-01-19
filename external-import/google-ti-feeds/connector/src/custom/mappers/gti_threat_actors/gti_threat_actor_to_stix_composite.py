"""Composite mapper that handles threat actor to country locations, identity, intrusion set, and relationships conversion in one step."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
    IdentityWithTiming,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_location import (
    GTIThreatActorToSTIXLocation,
    LocationWithTiming,
)
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIThreatActorToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI threat actor to country locations, identity, intrusion set, and relationships."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
        enable_threat_actor_aliases: bool = False,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            threat_actor: The GTI threat actor data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition
            enable_threat_actor_aliases: Whether to enable importing threat actor aliases

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.enable_threat_actor_aliases = enable_threat_actor_aliases

    def to_stix(self) -> list[Any]:
        """Convert the GTI threat actor to a list of STIX objects (country locations, sectors, intrusion set, relationships).

        Returns:
            list of STIX objects in order: [country_locations..., sectors..., intrusion_set, relationships...]

        """
        all_entities = []

        location_mapper = GTIThreatActorToSTIXLocation(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations_with_timing = location_mapper.to_stix_with_timing()
        country_locations = [item.location for item in locations_with_timing]
        all_entities.extend(country_locations)

        identity_mapper = GTIThreatActorToSTIXIdentity(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors_with_timing = identity_mapper.to_stix_with_timing()
        sectors = [item.identity for item in sectors_with_timing]
        all_entities.extend(sectors)

        intrusion_set_mapper = GTIThreatActorToSTIXIntrusionSet(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
            enable_threat_actor_aliases=self.enable_threat_actor_aliases,
        )
        intrusion_set = intrusion_set_mapper.to_stix()
        all_entities.append(intrusion_set)

        relationships = self._create_relationships(
            intrusion_set, locations_with_timing, sectors_with_timing
        )
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self,
        intrusion_set: Any,
        locations_with_timing: list[LocationWithTiming],
        sectors_with_timing: list[IdentityWithTiming],
    ) -> list[Any]:
        """Create relationships between the intrusion set and other entities.

        Args:
            intrusion_set: The intrusion set object
            locations_with_timing: list of LocationWithTiming objects containing location and timing data
            sectors_with_timing: list of IdentityWithTiming objects containing sector identity and timing data

        Returns:
            list of relationship objects

        """
        relationships: list[Any] = []

        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            return relationships

        attributes = self.threat_actor.attributes
        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        targeted_locations_with_timing = self._get_targeted_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in targeted_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' targets location '{location.name}'",
            )
            relationships.append(relationship)

        source_locations_with_timing = self._get_source_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in source_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' originates from location '{location.name}'",
            )
            relationships.append(relationship)

        for sector_with_timing in sectors_with_timing:
            sector = sector_with_timing.identity
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=sector.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=sector_with_timing.first_seen,
                stop_time=sector_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' targets sector '{sector.name}'",
            )
            relationships.append(relationship)

        return relationships

    def _get_targeted_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to targeted countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to targeted countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_targeted
        ]

    def _get_source_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to source countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to source countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_source
        ]
