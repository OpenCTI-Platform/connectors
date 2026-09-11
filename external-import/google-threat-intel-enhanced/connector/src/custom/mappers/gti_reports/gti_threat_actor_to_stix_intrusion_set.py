"""Converts a GTI threat actor to a STIX intrusion set object."""

from datetime import datetime
from typing import Any, List, Optional

from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
    SourceRegion,
    TargetedIndustry,
    TargetedRegion,
    ThreatActorModel,
)
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.stix.v21.models.sros.relationship_model import RelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, IntrusionSet, MarkingDefinition  # type: ignore


class GTIThreatActorToSTIXIntrusionSet(BaseMapper):
    """Converts a GTI threat actor to a STIX intrusion set object."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        **kwargs: Any,
    ) -> None:
        """Initialize the GTIThreatActorToSTIXIntrusionSet object.

        Args:
            threat_actor (GTIThreatActorData): The GTI threat actor data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Any]:
        """Convert the GTI threat actor to STIX intrusion set and related objects.

        Returns:
            List[Any]: List containing IntrusionSet, Location objects, and relationships.

        """
        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            raise ValueError("Invalid GTI threat actor data")

        attributes = self.threat_actor.attributes

        created = datetime.fromtimestamp(attributes.creation_date)
        modified = datetime.fromtimestamp(attributes.last_modification_date)

        aliases = self._extract_aliases(attributes)

        first_seen, last_seen = self._extract_seen_dates(attributes)

        primary_motivation, secondary_motivations = self._extract_motivations(
            attributes
        )

        name = attributes.name
        description = attributes.description

        intrusion_set_model = OctiIntrusionSetModel.create(
            name=name,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            description=description,
            aliases=aliases,
            first_seen=first_seen,
            last_seen=last_seen,
            primary_motivation=primary_motivation,
            secondary_motivations=secondary_motivations,
            created=created,
            modified=modified,
        )

        result: List[Any] = [intrusion_set_model]

        # Extract source locations (country of origin) and create relationships
        source_locations = self._extract_source_locations(
            attributes, intrusion_set_model, created, modified
        )
        result.extend(source_locations)

        # Extract targeted sectors and create "targets" relationships
        targeted_sectors = self._extract_targeted_sectors(
            attributes, intrusion_set_model, created, modified
        )
        result.extend(targeted_sectors)

        # Extract targeted regions and create "targets" relationships
        targeted_regions = self._extract_targeted_regions(
            attributes, intrusion_set_model, created, modified
        )
        result.extend(targeted_regions)

        return result

    def _extract_source_locations(
        self,
        attributes: ThreatActorModel,
        intrusion_set: Any,
        created: datetime,
        modified: datetime,
    ) -> List[Any]:
        """Extract source locations and create 'originates-from' relationships.

        Args:
            attributes: The threat actor attributes
            intrusion_set: The created IntrusionSet model
            created: Creation timestamp for relationships
            modified: Modification timestamp for relationships
            intrusion_set: The IntrusionSet model object

        Returns:
            List[Any]: List containing Location objects and relationship objects

        """
        result: List[Any] = []

        if (
            not hasattr(attributes, "source_regions_hierarchy")
            or not attributes.source_regions_hierarchy
        ):
            return result

        for source_region in attributes.source_regions_hierarchy:
            location = self._create_source_location(source_region)
            if location:
                result.append(location)
                # Create "originates-from" relationship between IntrusionSet and Location
                relationship = RelationshipModel(
                    relationship_type="originates-from",
                    source_ref=intrusion_set.id,
                    target_ref=location.id,
                    created=created,
                    modified=modified,
                    created_by_ref=self.organization.id,
                    object_marking_refs=[self.tlp_marking.id],
                )
                result.append(relationship)

        return result

    def _create_source_location(self, source_region: SourceRegion) -> Optional[Any]:
        """Create a Location object from a source region.

        Args:
            source_region: The source region data

        Returns:
            Optional[Any]: The Location model or None if no valid country

        """
        if not source_region.country or not source_region.country_iso2:
            return None

        location = OctiLocationModel.create_country(
            name=source_region.country,
            country_code=source_region.country_iso2,
            description=source_region.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return location

    @staticmethod
    def _extract_aliases(attributes: ThreatActorModel) -> Optional[List[str]]:
        """Extract aliases from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            Optional[List[str]]: Extracted aliases or None if no aliases exist

        """
        if (
            not hasattr(attributes, "alt_names_details")
            or not attributes.alt_names_details
        ):
            return None

        aliases = []
        for alt_name in attributes.alt_names_details:
            if hasattr(alt_name, "value") and alt_name.value:
                aliases.append(alt_name.value)

        return aliases if aliases else None

    @staticmethod
    def _extract_seen_dates(
        attributes: ThreatActorModel,
    ) -> tuple[Optional[datetime], Optional[datetime]]:
        """Extract first_seen and last_seen dates from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            tuple: (first_seen, last_seen) datetime objects or None if dates don't exist

        """
        first_seen = None
        if (
            hasattr(attributes, "first_seen_details")
            and attributes.first_seen_details
            and len(attributes.first_seen_details) > 0
            and hasattr(attributes.first_seen_details[0], "value")
            and attributes.first_seen_details[0].value
        ):
            try:
                first_seen_str = attributes.first_seen_details[0].value
                first_seen = datetime.strptime(first_seen_str, "%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                first_seen = None

        last_seen = None
        if (
            hasattr(attributes, "last_seen_details")
            and attributes.last_seen_details
            and len(attributes.last_seen_details) > 0
            and hasattr(attributes.last_seen_details[0], "value")
            and attributes.last_seen_details[0].value
        ):
            try:
                last_seen_str = attributes.last_seen_details[0].value
                last_seen = datetime.strptime(last_seen_str, "%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                last_seen = None

        return first_seen, last_seen

    def _extract_motivations(
        self, attributes: ThreatActorModel
    ) -> tuple[Optional[str], Optional[List[str]]]:
        """Extract primary and secondary motivations from threat actor attributes.

        Args:
            attributes: The threat actor attributes

        Returns:
            tuple: (primary_motivation, secondary_motivations) or (None, None) if motivations don't exist

        """
        if not hasattr(attributes, "motivations") or not attributes.motivations:
            return None, None

        motivations = []
        for motivation in attributes.motivations:
            if hasattr(motivation, "value") and motivation.value:
                mapped_motivation = self._map_gti_motivation_to_stix_motivation(
                    motivation.value
                )
                if mapped_motivation:
                    motivations.append(mapped_motivation)
                else:
                    motivations.append(AttackMotivationOV.UNPREDICTABLE)

        if not motivations:
            return None, None

        primary_motivation = motivations[0]
        secondary_motivations = motivations[1:] if len(motivations) > 1 else None

        return primary_motivation, secondary_motivations

    @staticmethod
    def _map_gti_motivation_to_stix_motivation(motivation: str) -> Optional[str]:
        """Map GTI motivation to STIX attack motivation.

        Args:
            motivation: The GTI motivation

        Returns:
            Optional[str]: Mapped STIX attack motivation or None if no mapping exists

        """
        return AttackMotivationOV(motivation)

    def _extract_targeted_sectors(
        self,
        attributes: ThreatActorModel,
        intrusion_set: Any,
        created: datetime,
        modified: datetime,
    ) -> List[Any]:
        """Extract targeted sectors and create 'targets' relationships.

        Args:
            attributes: The threat actor attributes
            intrusion_set: The created IntrusionSet model
            created: Creation timestamp for relationships
            modified: Modification timestamp for relationships

        Returns:
            List[Any]: List containing Sector Identity objects and relationship objects

        """
        result: List[Any] = []

        if (
            not hasattr(attributes, "targeted_industries_tree")
            or not attributes.targeted_industries_tree
        ):
            return result

        seen_sectors: set = set()

        for industry in attributes.targeted_industries_tree:
            sector = self._create_targeted_sector(industry, seen_sectors)
            if sector:
                result.append(sector)
                # Create "targets" relationship between IntrusionSet and Sector
                relationship = RelationshipModel(
                    relationship_type="targets",
                    source_ref=intrusion_set.id,
                    target_ref=sector.id,
                    created=created,
                    modified=modified,
                    created_by_ref=self.organization.id,
                    object_marking_refs=[self.tlp_marking.id],
                )
                result.append(relationship)

        return result

    def _create_targeted_sector(
        self, industry: TargetedIndustry, seen_sectors: set
    ) -> Optional[Any]:
        """Create a Sector Identity object from a targeted industry.

        Args:
            industry: The targeted industry data
            seen_sectors: Set of already processed sector names to avoid duplicates

        Returns:
            Optional[Any]: The Sector Identity model or None if no valid industry group

        """
        if not industry.industry_group:
            return None

        sector_name = industry.industry_group

        # Avoid duplicates within this threat actor
        if sector_name in seen_sectors:
            return None
        seen_sectors.add(sector_name)

        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            description=industry.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return sector

    def _extract_targeted_regions(
        self,
        attributes: ThreatActorModel,
        intrusion_set: Any,
        created: datetime,
        modified: datetime,
    ) -> List[Any]:
        """Extract targeted regions and create 'targets' relationships.

        Args:
            attributes: The threat actor attributes
            intrusion_set: The created IntrusionSet model
            created: Creation timestamp for relationships
            modified: Modification timestamp for relationships

        Returns:
            List[Any]: List containing Location objects and relationship objects

        """
        result: List[Any] = []

        if (
            not hasattr(attributes, "targeted_regions_hierarchy")
            or not attributes.targeted_regions_hierarchy
        ):
            return result

        seen_countries: set = set()

        for region in attributes.targeted_regions_hierarchy:
            location = self._create_targeted_location(region, seen_countries)
            if location:
                result.append(location)
                # Create "targets" relationship between IntrusionSet and Location
                relationship = RelationshipModel(
                    relationship_type="targets",
                    source_ref=intrusion_set.id,
                    target_ref=location.id,
                    created=created,
                    modified=modified,
                    created_by_ref=self.organization.id,
                    object_marking_refs=[self.tlp_marking.id],
                )
                result.append(relationship)

        return result

    def _create_targeted_location(
        self, region: TargetedRegion, seen_countries: set
    ) -> Optional[Any]:
        """Create a Location object from a targeted region.

        Args:
            region: The targeted region data
            seen_countries: Set of already processed country codes to avoid duplicates

        Returns:
            Optional[Any]: The Location model or None if no valid country

        """
        if not region.country or not region.country_iso2:
            return None

        # Avoid duplicates within this threat actor
        if region.country_iso2 in seen_countries:
            return None
        seen_countries.add(region.country_iso2)

        location = OctiLocationModel.create_country(
            name=region.country,
            country_code=region.country_iso2,
            description=region.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        return location
