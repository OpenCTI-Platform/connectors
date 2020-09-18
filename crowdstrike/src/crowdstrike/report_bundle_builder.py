# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report bundle builder module."""

import logging
from typing import List, Mapping, Optional, Tuple

from crowdstrike_client.api.models.report import Report

from stix2 import (
    Bundle,
    ExternalReference,
    Identity,
    IntrusionSet,
    KillChainPhase,
    Malware,
    MarkingDefinition,
    Relationship,
    Report as STIXReport,
)
from stix2.v20 import _DomainObject

from crowdstrike.utils import (
    create_external_reference,
    create_intrusion_set_from_actor,
    create_malware,
    create_object_refs,
    create_organization,
    create_sectors_from_entities,
    create_stix2_report_from_report,
    create_targets_relationships,
    create_uses_relationships,
    datetime_utc_epoch_start,
    datetime_utc_now,
    create_regions_and_countries_from_entities,
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

    def _create_malwares(self) -> List[Malware]:
        malwares = []
        for name, stix_id in self.guessed_malwares.items():
            logger.info("Creating malware '%s' (%s)", name, stix_id)

            aliases: List[str] = []
            kill_chain_phases: List[KillChainPhase] = []
            external_references: List[ExternalReference] = []

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
        report_actors = self.report.actors
        if report_actors is None:
            return []

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
                actor, self.author, actor_external_references, self.object_marking_refs
            )

            intrusion_sets.append(intrusion_set)
        return intrusion_sets

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
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
        self, sources: List[_DomainObject], targets: List[_DomainObject]
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
        target_industries = self.report.target_industries
        if target_industries is None:
            return []
        return create_sectors_from_entities(target_industries, self.author)

    def _create_targeted_regions_and_countries(
        self,
    ) -> Tuple[List[Identity], List[Identity]]:
        target_regions: List[Identity] = []
        target_countries: List[Identity] = []

        report_target_countries = self.report.target_countries
        if report_target_countries:
            (
                target_regions,
                target_countries,
            ) = create_regions_and_countries_from_entities(
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

    def _create_report(self, object_refs: List[_DomainObject]) -> STIXReport:
        files = self._create_files()

        stix_report = create_stix2_report_from_report(
            self.report,
            self.author,
            self.source_name,
            object_refs,
            self.object_marking_refs,
            self.report_status,
            self.report_type,
            self.confidence_level,
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
