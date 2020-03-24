# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report bundle builder module."""

import logging
from typing import List, Tuple, Mapping, Optional

from crowdstrike_client.api.models.report import Report
from stix2 import (
    Bundle,
    ExternalReference,
    IntrusionSet,
    Relationship,
    Identity,
    Report as STIXReport,
    MarkingDefinition,
    Malware,
)
from stix2.core import STIXDomainObject

from crowdstrike.utils import (
    create_external_reference,
    create_intrusion_set_from_actor,
    create_uses_relationships,
    create_sectors_from_entities,
    create_targets_relationships,
    split_countries_and_regions,
    create_object_refs,
    create_organization,
    create_tags,
    create_stix2_report_from_report,
    datetime_utc_epoch_start,
    datetime_utc_now,
    create_malware,
)


logger = logging.getLogger(__name__)


class ReportBundleBuilder:
    """Report bundle builder."""

    _DUMMY_OBJECT_NAME = "CS EMPTY REPORT"

    def __init__(
        self,
        report: Report,
        author: Identity,
        source_name: str,
        object_marking_refs: List[MarkingDefinition],
        report_status: int,
        report_type: str,
        confidence_level: int,
        guessed_malwares: Mapping[str, str],
        report_file: Optional[Mapping[str, str]] = None,
    ) -> None:
        """Initialize report bundle builder."""
        self.report = report
        self.author = author
        self.source_name = source_name
        self.object_marking_refs = object_marking_refs
        self.confidence_level = confidence_level
        self.report_status = report_status
        self.report_type = report_type
        self.report_file = report_file
        self.guessed_malwares = guessed_malwares

        # Use report dates for first seen and last seen.
        first_seen = self.report.created_date
        if first_seen is None:
            first_seen = datetime_utc_epoch_start()

        last_seen = self.report.last_modified_date
        if last_seen is None:
            last_seen = datetime_utc_now()

        if first_seen > last_seen:
            logger.warning(
                "First seen is greater than last seen for report: %s", self.report.name
            )
            first_seen, last_seen = last_seen, first_seen

        self.first_seen = first_seen
        self.last_seen = last_seen

    def _create_external_references(self) -> List[ExternalReference]:
        external_references = []
        report_url = self.report.url
        if report_url:
            external_reference = create_external_reference(
                self.source_name, str(self.report.id), report_url
            )
            external_references.append(external_reference)
        return external_references

    def _create_malwares(self) -> List[Malware]:
        malwares = []
        for name, stix_id in self.guessed_malwares.items():
            logger.info("Creating malware '%s' (%s)", name, stix_id)

            aliases = []
            kill_chain_phases = []
            external_references = []

            malware = create_malware(
                name,
                aliases,
                self.author,
                kill_chain_phases,
                external_references,
                self.object_marking_refs,
                malware_id=stix_id,
            )
            malwares.append(malware)
        return malwares

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        primary_motivation = None
        secondary_motivation = None

        report_actors = self.report.actors

        intrusion_sets = []
        for actor in report_actors:
            actor_external_references = []

            actor_url = actor.url
            if actor_url:
                actor_external_reference = create_external_reference(
                    self.source_name, str(actor.id), actor_url
                )
                actor_external_references.append(actor_external_reference)

            intrusion_set = create_intrusion_set_from_actor(
                actor,
                self.author,
                primary_motivation,
                secondary_motivation,
                actor_external_references,
                self.object_marking_refs,
            )

            intrusion_sets.append(intrusion_set)
        return intrusion_sets

    def _create_uses_relationships(
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
    ) -> List[Relationship]:
        return create_uses_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

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

    def _create_targeted_sectors(self) -> List[Identity]:
        return create_sectors_from_entities(self.report.target_industries, self.author)

    def _create_targeted_regions_and_countries(
        self,
    ) -> Tuple[List[Identity], List[Identity]]:
        target_regions: List[Identity] = []
        target_countries: List[Identity] = []

        report_target_countries = self.report.target_countries
        if report_target_countries:
            target_regions, target_countries = split_countries_and_regions(
                report_target_countries, self.author
            )

        return target_regions, target_countries

    def _create_dummy_object(self) -> Identity:
        return create_organization(self._DUMMY_OBJECT_NAME, self.author)

    def _create_files(self) -> List[Mapping[str, str]]:
        files = []
        if self.report_file is not None:
            files.append(self.report_file)
        return files

    def _create_tags(self) -> List[Mapping[str, str]]:
        return create_tags(self.report.tags, self.source_name)

    def _create_report(self, object_refs: List[STIXDomainObject]) -> STIXReport:
        external_references = self._create_external_references()
        tags = self._create_tags()
        files = self._create_files()

        stix_report = create_stix2_report_from_report(
            self.report,
            self.author,
            object_refs,
            external_references,
            self.object_marking_refs,
            self.report_status,
            self.report_type,
            self.confidence_level,
            tags,
            files,
        )
        return stix_report

    def build(self) -> Bundle:
        """Build report bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_marking_refs)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Intrusion sets use malwares, add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors, add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Malwares target sectors, add to bundle.
        malwares_target_sectors = self._create_targets_relationships(
            malwares, target_sectors
        )
        bundle_objects.extend(malwares_target_sectors)

        # Create targeted countries and regions and add to bundle.
        target_regions, target_countries = self._create_targeted_regions_and_countries()
        bundle_objects.extend(target_regions)
        bundle_objects.extend(target_countries)

        # Intrusion sets target regions, add to bundle.
        intrusion_sets_target_regions = self._create_targets_relationships(
            intrusion_sets, target_regions
        )
        bundle_objects.extend(intrusion_sets_target_regions)

        # Intrusion sets target countries, add to bundle.
        intrusion_sets_target_countries = self._create_targets_relationships(
            intrusion_sets, target_countries
        )
        bundle_objects.extend(intrusion_sets_target_countries)

        # Malwares target regions, add to bundle.
        malwares_target_regions = self._create_targets_relationships(
            malwares, target_regions
        )
        bundle_objects.extend(malwares_target_regions)

        # Malwares target countries, add to bundle.
        malwares_target_countries = self._create_targets_relationships(
            malwares, target_countries
        )
        bundle_objects.extend(malwares_target_countries)

        # Create object references for the report.
        object_refs = create_object_refs(
            malwares,
            intrusion_sets,
            intrusion_sets_use_malwares,
            target_sectors,
            intrusion_sets_target_sectors,
            malwares_target_sectors,
            target_regions,
            intrusion_sets_target_regions,
            malwares_target_regions,
            target_countries,
            intrusion_sets_target_countries,
            malwares_target_countries,
        )

        # TODO: Ignore reports without any references or not?
        # Hack, the report must have at least on object reference.
        if not object_refs:
            dummy_object = self._create_dummy_object()

            bundle_objects.append(dummy_object)
            object_refs.append(dummy_object)

        stix_report = self._create_report(object_refs)
        bundle_objects.append(stix_report)

        return Bundle(objects=bundle_objects)
