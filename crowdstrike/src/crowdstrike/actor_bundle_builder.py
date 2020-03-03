# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike actor bundle builder module."""

import logging
from typing import List, Tuple

from crowdstrike_client.api.models.actor import Actor
from pycti.utils.constants import CustomProperties
from stix2 import (
    Bundle,
    ExternalReference,
    IntrusionSet,
    Identity,
    Relationship,
    MarkingDefinition,
)
from stix2.core import STIXDomainObject

from crowdstrike.utils import (
    create_external_reference,
    remove_html_tags,
    create_sectors_from_entities,
    create_targets_relationships,
    split_countries_and_regions,
    datetime_utc_now,
    datetime_utc_epoch_start,
)


logger = logging.getLogger(__name__)


class ActorBundleBuilder:
    """Actor bundle builder."""

    def __init__(
        self,
        actor: Actor,
        author: Identity,
        source_name: str,
        object_marking_refs: List[MarkingDefinition],
        confidence_level: int,
    ) -> None:
        """Initialize actor bundle builder."""
        self.actor = actor
        self.author = author
        self.source_name = source_name
        self.object_marking_refs = object_marking_refs
        self.confidence_level = confidence_level

        first_seen = self.actor.first_activity_date
        if first_seen is None:
            first_seen = datetime_utc_epoch_start()

        last_seen = self.actor.last_activity_date
        if last_seen is None:
            last_seen = datetime_utc_now()

        if first_seen > last_seen:
            logger.warning(
                "First seen is greater than last seen for actor: %s", self.actor.name
            )
            first_seen, last_seen = last_seen, first_seen

        self.first_seen = first_seen
        self.last_seen = last_seen

    def _create_external_references(self) -> List[ExternalReference]:
        external_references = []
        actor_url = self.actor.url
        if actor_url:
            external_reference = create_external_reference(
                self.source_name, str(self.actor.id), actor_url
            )
            external_references.append(external_reference)
        return external_references

    def _create_intrusion_set(self) -> IntrusionSet:
        external_references = self._create_external_references()

        name = self.actor.name
        if name is None:
            name = f"NO_ACTOR_NAME{self.actor.id}"

        alias = name.replace(" ", "")
        aliases = [alias]

        known_as = self.actor.known_as
        for known_alias in known_as.split(","):
            aliases.append(known_alias.strip())

        description = "NO DESCRIPTION"
        if self.actor.description is not None and self.actor.description:
            description = self.actor.description
        elif self.actor.rich_text_description is not None:
            description = remove_html_tags(self.actor.rich_text_description)
        elif self.actor.short_description is not None:
            description = self.actor.short_description

        intrusion_set = IntrusionSet(
            created_by_ref=self.author,
            name=name,
            description=description,
            aliases=aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            labels=["intrusion-set"],
            external_references=external_references,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                CustomProperties.ALIASES: aliases,
                CustomProperties.FIRST_SEEN: self.first_seen,
                CustomProperties.LAST_SEEN: self.last_seen,
            },
        )
        return intrusion_set

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        return [self._create_intrusion_set()]

    def _create_targeted_sectors(self) -> List[Identity]:
        target_sectors = []
        actor_target_industries = self.actor.target_industries
        if actor_target_industries is not None:
            target_sectors = create_sectors_from_entities(
                actor_target_industries, self.author
            )
        return target_sectors

    def _create_targets_relationships(
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
    ) -> List[Relationship]:
        return create_targets_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

    def _create_targeted_regions_and_countries(
        self,
    ) -> Tuple[List[Identity], List[Identity]]:
        target_regions: List[Identity] = []
        target_countries: List[Identity] = []

        actor_target_countries = self.actor.target_countries
        if actor_target_countries is not None:
            target_regions, target_countries = split_countries_and_regions(
                actor_target_countries, self.author
            )

        return target_regions, target_countries

    def build(self) -> Bundle:
        """Build actor bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_marking_refs)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors, add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Create target regions and countries and add to bundle.
        target_regions, target_countries = self._create_targeted_regions_and_countries()
        bundle_objects.extend(target_regions)
        bundle_objects.extend(target_countries)

        # Intrusion sets target regions, add to bundle.
        intrusion_sets_target_regions = self._create_targets_relationships(
            intrusion_sets, target_regions
        )
        bundle_objects.extend(intrusion_sets_target_regions)

        # Create relationships between intrusion sets and targeted countries, add to bundle.
        intrusion_sets_target_countries = self._create_targets_relationships(
            intrusion_sets, target_countries
        )
        bundle_objects.extend(intrusion_sets_target_countries)

        return Bundle(objects=bundle_objects)
