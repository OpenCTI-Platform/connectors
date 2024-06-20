# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report builder module."""

import logging
from typing import List, Mapping, Optional, Tuple, Union

from crowdstrike_feeds_services.utils import (
    create_external_reference,
    create_intrusion_set_from_name,
    create_malware,
    create_object_refs,
    create_organization,
    create_regions_and_countries_from_entities,
    create_sectors_from_entities,
    create_stix2_report_from_report,
    create_targets_relationships,
    create_uses_relationships,
    datetime_utc_epoch_start,
    datetime_utc_now,
    normalize_start_time_and_stop_time,
    timestamp_to_datetime,
)
from stix2 import (
    Bundle,
    ExternalReference,
    Identity,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Relationship,
)
from stix2 import Report as STIXReport  # type: ignore
from stix2.v21 import _DomainObject, _RelationshipObject  # type: ignore

logger = logging.getLogger(__name__)


class ReportBundleBuilder:
    """Report bundle builder."""

    _DUMMY_OBJECT_NAME = "CS EMPTY REPORT"

    def __init__(
        self,
        report: dict,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
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
        self.object_markings = object_markings
        self.confidence_level = confidence_level
        self.report_status = report_status
        self.report_type = report_type
        self.report_file = report_file
        self.guessed_malwares = guessed_malwares

        # Use report dates for start time and stop time.
        start_time = timestamp_to_datetime(self.report["created_date"])
        if start_time is None:
            start_time = datetime_utc_epoch_start()

        stop_time = timestamp_to_datetime(self.report["last_modified_date"])
        if stop_time is None:
            stop_time = datetime_utc_now()

        start_time, stop_time = normalize_start_time_and_stop_time(
            start_time, stop_time
        )

        self.start_time = start_time
        self.stop_time = stop_time

    def _create_malwares(self) -> List[Malware]:
        malwares = []

        for name, malware_id in self.guessed_malwares.items():
            logger.info("Creating guessed malware '%s' (%s)...", name, malware_id)

            malware = self._create_malware(malware_id, name)
            malwares.append(malware)

        return malwares

    def _create_malware(self, malware_id: str, name: str) -> Malware:
        return create_malware(
            name,
            malware_id=malware_id,
            created_by=self.author,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        report_actors = self.report["actors"]
        if report_actors is None:
            return []

        intrusion_sets = []

        for actor in report_actors:
            intrusion_set = self._create_intrusion_set_from_actor(actor)
            intrusion_sets.append(intrusion_set)

        return intrusion_sets

    def _create_intrusion_set_from_actor(self, actor: dict) -> Optional[IntrusionSet]:
        actor_name = actor["name"]
        if actor_name is None or not actor_name:
            return None

        external_references = []

        actor_url = actor["url"]
        if actor_url is not None and actor_url:
            external_reference = self._create_external_reference(
                str(actor["id"]), actor_url
            )
            external_references.append(external_reference)

        return create_intrusion_set_from_name(
            actor_name,
            self.author,
            self.confidence_level,
            external_references,
            self.object_markings,
        )

    def _create_external_reference(
        self, external_id: str, url: str
    ) -> ExternalReference:
        return create_external_reference(self.source_name, external_id, url)

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_uses_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            self.start_time,
            self.stop_time,
        )

    def _create_targets_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_targets_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            self.start_time,
            self.stop_time,
        )

    def _create_targeted_sectors(self) -> List[Identity]:
        target_industries = self.report["target_industries"]
        if target_industries is None or not target_industries:
            return []

        return create_sectors_from_entities(target_industries, self.author)

    def _create_targeted_regions_and_countries(
        self,
    ) -> Tuple[List[Location], List[Location]]:
        report_target_countries = self.report["target_countries"]
        if report_target_countries is None or not report_target_countries:
            return [], []

        return self._create_regions_and_countries_from_entities(report_target_countries)

    def _create_regions_and_countries_from_entities(
        self, entities: List
    ) -> Tuple[List[Location], List[Location]]:
        return create_regions_and_countries_from_entities(entities, self.author)

    def _create_files(self) -> List[Mapping[str, str]]:
        files = []
        if self.report_file is not None:
            files.append(self.report_file)
        return files

    def _create_report(
        self, objects: List[Union[_DomainObject, _RelationshipObject]]
    ) -> STIXReport:
        files = self._create_files()
        return self._create_stix2_report_from_report(objects, files)

    def _create_stix2_report_from_report(
        self,
        objects: List[Union[_DomainObject, _RelationshipObject]],
        files: List[Mapping[str, Union[str, bool]]],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            self.report,
            self.source_name,
            self.author,
            objects,
            [self.report_type],
            self.confidence_level,
            self.object_markings,
            self.report_status,
            x_opencti_files=files,
        )

    def _create_dummy_object(self) -> Identity:
        return create_organization(self._DUMMY_OBJECT_NAME, self.author)

    def build(self) -> Bundle:
        """Build report bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares and add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors and add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Malwares target sectors and add to bundle.
        malwares_target_sectors = self._create_targets_relationships(
            malwares, target_sectors
        )
        bundle_objects.extend(malwares_target_sectors)

        # Create targeted countries and regions and add to bundle.
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

        # Malwares target regions and add to bundle.
        malwares_target_regions = self._create_targets_relationships(
            malwares, target_regions
        )
        bundle_objects.extend(malwares_target_regions)

        # Malwares target countries and add to bundle.
        malwares_target_countries = self._create_targets_relationships(
            malwares, target_countries
        )
        bundle_objects.extend(malwares_target_countries)

        # Create object references for the report.
        object_refs = create_object_refs(
            intrusion_sets,
            malwares,
            intrusion_sets_use_malwares,
            target_sectors,
            intrusion_sets_target_sectors,
            malwares_target_sectors,
            target_regions,
            target_countries,
            intrusion_sets_target_regions,
            intrusion_sets_target_countries,
            malwares_target_regions,
            malwares_target_countries,
        )

        # TODO: Ignore reports without any references or not?
        # Hack, the report must have at least on object reference.
        if not object_refs:
            dummy_object = self._create_dummy_object()

            bundle_objects.append(dummy_object)
            object_refs.append(dummy_object)

        report = self._create_report(object_refs)
        bundle_objects.append(report)

        return Bundle(objects=bundle_objects, allow_custom=True)
