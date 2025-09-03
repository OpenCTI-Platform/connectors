"""Composite mapper that handles threat actor to country locations, identity, intrusion set, and relationships conversion in one step."""

from datetime import datetime, timezone
from typing import Any, List

from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_location import (
    GTIThreatActorToSTIXLocation,
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
    ) -> None:
        """Initialize the composite mapper.

        Args:
            threat_actor: The GTI threat actor data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Any]:
        """Convert the GTI threat actor to a list of STIX objects (country locations, sectors, intrusion set, relationships).

        Returns:
            List of STIX objects in order: [country_locations..., sectors..., intrusion_set, relationships...]

        """
        all_entities = []

        location_mapper = GTIThreatActorToSTIXLocation(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        country_locations = location_mapper.to_stix()
        all_entities.extend(country_locations)

        identity_mapper = GTIThreatActorToSTIXIdentity(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors = identity_mapper.to_stix()
        all_entities.extend(sectors)

        intrusion_set_mapper = GTIThreatActorToSTIXIntrusionSet(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        intrusion_set = intrusion_set_mapper.to_stix()
        all_entities.append(intrusion_set)

        relationships = self._create_relationships(
            intrusion_set, country_locations, sectors
        )
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self, intrusion_set: Any, country_locations: List[Any], sectors: List[Any]
    ) -> List[Any]:
        """Create relationships between the intrusion set and other entities.

        Args:
            intrusion_set: The intrusion set object
            country_locations: List of country location objects
            sectors: List of sector identity objects

        Returns:
            List of relationship objects

        """
        relationships: List[Any] = []

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

        targeted_country_locations = self._get_targeted_country_locations(
            country_locations
        )
        for location in targeted_country_locations:
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Threat actor '{attributes.name}' targets location '{location.name}'",
            )
            relationships.append(relationship)

        source_country_locations = self._get_source_country_locations(country_locations)
        for location in source_country_locations:
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Threat actor '{attributes.name}' originates from location '{location.name}'",
            )
            relationships.append(relationship)

        for sector in sectors:
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=sector.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Threat actor '{attributes.name}' targets sector '{sector.name}'",
            )
            relationships.append(relationship)

        return relationships

    def _get_targeted_country_locations(
        self, country_locations: List[Any]
    ) -> List[Any]:
        """Get locations that correspond to targeted countries.

        Args:
            country_locations: List of all country location objects

        Returns:
            List of location objects that correspond to targeted countries

        """
        targeted_locations: List[Any] = []

        if (
            not self.threat_actor.attributes
            or not self.threat_actor.attributes.targeted_regions_hierarchy
        ):
            return targeted_locations

        targeted_country_names = set()
        for region in self.threat_actor.attributes.targeted_regions_hierarchy:
            if region.country:
                targeted_country_names.add(region.country.lower())

        for location in country_locations:
            if hasattr(location, "name") and location.name:
                if location.name.lower() in targeted_country_names:
                    targeted_locations.append(location)

        return targeted_locations

    def _get_source_country_locations(self, country_locations: List[Any]) -> List[Any]:
        """Get locations that correspond to source countries.

        Args:
            country_locations: List of all country location objects

        Returns:
            List of location objects that correspond to source countries

        """
        source_locations: List[Any] = []

        if (
            not self.threat_actor.attributes
            or not self.threat_actor.attributes.source_regions_hierarchy
        ):
            return source_locations

        source_country_names = set()
        for region in self.threat_actor.attributes.source_regions_hierarchy:
            if region.country:
                source_country_names.add(region.country.lower())

        for location in country_locations:
            if hasattr(location, "name") and location.name:
                if location.name.lower() in source_country_names:
                    source_locations.append(location)

        return source_locations
