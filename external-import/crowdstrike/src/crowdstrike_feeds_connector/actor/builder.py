# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actor builder module."""

import logging
from typing import List, Optional, Tuple

from crowdstrike_feeds_services.utils import (
    create_external_reference,
    create_intrusion_set,
    create_originates_from_relationships,
    create_regions_and_countries_from_entities,
    create_sectors_from_entities,
    create_targets_relationships,
    datetime_utc_epoch_start,
    datetime_utc_now,
    normalize_start_time_and_stop_time,
    remove_html_tags,
    timestamp_to_datetime,
)
from stix2 import Identity  # type: ignore
from stix2 import (
    Bundle,
    ExternalReference,
    IntrusionSet,
    Location,
    MarkingDefinition,
    Relationship,
)
from stix2.v21 import _DomainObject  # type: ignore

logger = logging.getLogger(__name__)


class ActorBundleBuilder:
    """Actor bundle builder."""

    _CS_MOTIVATION_CRIMINAL = "Criminal"
    _CS_MOTIVATION_DESTRUCTION = "Destruction"
    _CS_MOTIVATION_ESPIONAGE = "Espionage"
    _CS_MOTIVATION_HACKTIVIST = "Hacktivist"

    _CS_MOTIVATION_TO_STIX_MOTIVATION = {
        _CS_MOTIVATION_CRIMINAL: "personal-gain",
        _CS_MOTIVATION_DESTRUCTION: "dominance",
        _CS_MOTIVATION_ESPIONAGE: "organizational-gain",
        _CS_MOTIVATION_HACKTIVIST: "ideology",
    }

    def __init__(
        self,
        actor: dict,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        confidence_level: int,
    ) -> None:
        """Initialize actor bundle builder."""
        self.actor = actor
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.confidence_level = confidence_level

        first_seen = timestamp_to_datetime(self.actor["first_activity_date"])
        if first_seen is None:
            first_seen = datetime_utc_epoch_start()

        last_seen = timestamp_to_datetime(self.actor["last_activity_date"])
        if last_seen is None:
            last_seen = datetime_utc_now()

        first_seen, last_seen = normalize_start_time_and_stop_time(
            first_seen, last_seen
        )

        self.first_seen = first_seen
        self.last_seen = last_seen

    def _create_external_references(self) -> List[ExternalReference]:
        external_references = []
        actor_url = self.actor["url"]
        if actor_url:
            external_reference = create_external_reference(
                self.source_name, str(self.actor["id"]), actor_url
            )
            external_references.append(external_reference)
        return external_references

    def _create_intrusion_set(self) -> IntrusionSet:
        description = self._get_description()
        aliases = self._get_aliases()
        primary_motivation, secondary_motivations = self._get_motivations()
        external_references = self._create_external_references()

        return create_intrusion_set(
            self.actor["name"],
            created_by=self.author,
            description=description,
            aliases=aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            primary_motivation=primary_motivation,
            secondary_motivations=secondary_motivations,
            confidence=self.confidence_level,
            external_references=external_references,
            object_markings=self.object_markings,
        )

    def _get_description(self) -> Optional[str]:
        actor = self.actor

        actor_description = actor["description"]
        actor_rich_text_description = actor["rich_text_description"]
        actor_short_description = actor["short_description"]

        final_description = None

        if actor_description is not None and actor_description:
            final_description = actor_description
        elif actor_rich_text_description is not None and actor_rich_text_description:
            final_description = remove_html_tags(actor_rich_text_description)
        elif actor_short_description:
            final_description = actor_short_description

        return final_description

    def _get_aliases(self) -> List[str]:
        actor = self.actor

        name = actor["name"]
        known_as = actor["known_as"]

        aliases = [name.replace(" ", "")]

        for known_alias in known_as.split(","):
            known_alias = known_alias.strip()
            if not known_alias:
                continue

            aliases.append(known_alias)

        # Remove duplicates.
        aliases = list(dict.fromkeys(aliases))

        if name in aliases:
            aliases.remove(name)

        return aliases

    def _get_motivations(self) -> Tuple[Optional[str], Optional[List[str]]]:
        actor = self.actor

        actor_motivations = actor["motivations"]
        if actor_motivations is None:
            return None, None

        motivations = []

        for actor_motivation in actor_motivations:
            value = actor_motivation["value"]
            if not value:
                continue

            motivation = self._CS_MOTIVATION_TO_STIX_MOTIVATION.get(value)
            if motivation is None:
                logger.warning("Unsupported actor motivation: %s", value)
                continue

            motivations.append(motivation)

        if len(motivations) == 0:
            return None, None
        elif len(motivations) == 1:
            return motivations[0], None
        else:
            return motivations[0], motivations[1:]

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        return [self._create_intrusion_set()]

    def _create_origin_regions_and_countries(
        self,
    ) -> Tuple[List[Location], List[Location]]:
        actor_origins = self.actor["origins"]
        if actor_origins is None:
            return [], []

        return self._create_regions_and_countries_from_entities(actor_origins)

    def _create_targeted_regions_and_countries(
        self,
    ) -> Tuple[List[Location], List[Location]]:
        actor_target_countries = self.actor["target_countries"]
        if actor_target_countries is None:
            return [], []

        return self._create_regions_and_countries_from_entities(actor_target_countries)

    def _create_regions_and_countries_from_entities(
        self, entities: List
    ) -> Tuple[List[Location], List[Location]]:
        return create_regions_and_countries_from_entities(entities, self.author)

    def _create_targeted_sectors(self) -> List[Identity]:
        actor_target_industries = self.actor["target_industries"]
        if actor_target_industries is None:
            return []

        return self._create_sectors_from_entities(actor_target_industries)

    def _create_sectors_from_entities(self, entities: List) -> List[Identity]:
        return create_sectors_from_entities(entities, self.author)

    def _create_targets_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_targets_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
            stop_time=self.last_seen,
        )

    def _create_originates_from_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_originates_from_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
            stop_time=self.last_seen,
        )

    def build(self) -> Bundle:
        """Build actor bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create origin regions and countries and add to bundle.
        origin_regions, origin_countries = self._create_origin_regions_and_countries()
        bundle_objects.extend(origin_regions)
        bundle_objects.extend(origin_countries)

        # Intrusion sets originate from regions and add to bundle.
        intrusion_sets_originate_from_regions = (
            self._create_originates_from_relationships(intrusion_sets, origin_regions)
        )
        bundle_objects.extend(intrusion_sets_originate_from_regions)

        # Intrusion sets originate from countries and add to bundle.
        intrusion_sets_originate_from_countries = (
            self._create_originates_from_relationships(intrusion_sets, origin_countries)
        )
        bundle_objects.extend(intrusion_sets_originate_from_countries)

        # Create target regions and countries and add to bundle.
        target_regions, target_countries = self._create_targeted_regions_and_countries()
        bundle_objects.extend(target_regions)
        bundle_objects.extend(target_countries)

        # Intrusion sets target regions and add to bundle.
        intrusion_sets_target_regions = self._create_targets_relationships(
            intrusion_sets, target_regions
        )
        bundle_objects.extend(intrusion_sets_target_regions)

        # Intrusion sets target countries and add to bundle.
        intrusion_sets_target_countries = self._create_targets_relationships(
            intrusion_sets, target_countries
        )
        bundle_objects.extend(intrusion_sets_target_countries)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors, add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        return Bundle(objects=bundle_objects, allow_custom=True)
