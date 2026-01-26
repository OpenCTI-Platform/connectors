# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report builder module."""

import logging
from collections.abc import Sequence
from typing import Any, Iterable, Mapping, cast

from crowdstrike_feeds_connector.related_actors.builder import RelatedActorBundleBuilder
from crowdstrike_feeds_services.utils import (
    create_external_reference,
    create_malware,
    create_object_refs,
    create_organization,
    create_regions_and_countries_from_entities,
    create_sectors_from_entities,
    create_stix2_report_from_report,
    create_targets_relationships,
    create_uses_relationships,
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
from stix2 import Report as STIXReport
from stix2.v21 import _DomainObject, _RelationshipObject

logger = logging.getLogger(__name__)


class ReportBundleBuilder:
    """Report bundle builder."""

    _DUMMY_OBJECT_NAME = "CS EMPTY REPORT"

    def __init__(
        self,
        report: dict,
        author: Identity,
        source_name: str,
        object_markings: list[MarkingDefinition],
        report_status: int,
        report_type: str,
        confidence_level: int,
        report_file: Mapping[str, str | bool] | None = None,
        related_indicators: Sequence[_DomainObject] | None = None,
        report_guess_relations: bool = False,
        malwares_from_field: list[dict] | None = None,
        scopes: set[str] | None = None,
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
        self.related_indicators = list(related_indicators or [])
        self.report_guess_relations = report_guess_relations
        self.malwares_from_field = malwares_from_field or []
        self.related_actor_builder_cls = RelatedActorBundleBuilder
        self.scopes = scopes

        # Use report dates for start time and stop time.
        start_time = timestamp_to_datetime(self.report["created_date"])

        # Try to use a meaningful end time if present; otherwise fall back to start_time.
        stop_ts = (
            self.report.get("last_updated")
            or self.report.get("last_modified_date")
            or self.report.get("updated_date")
            or self.report.get("modified")
            or self.report.get("last_activity_date")
        )
        if isinstance(stop_ts, int) and stop_ts > 0:
            stop_time = timestamp_to_datetime(stop_ts)
        else:
            stop_time = start_time

        start_time, stop_time = normalize_start_time_and_stop_time(
            start_time, stop_time
        )

        self.start_time = start_time
        self.stop_time = stop_time

    def _create_malwares(self) -> list[Malware]:
        malwares = []

        if self.malwares_from_field:
            for malware_item in self.malwares_from_field:
                family_name = malware_item.get("family_name")
                if family_name:
                    logger.info("Creating malware from field '%s'...", family_name)
                    malware = self._create_malware(family_name, is_family=True)
                    malwares.append(malware)

        return malwares

    def _create_malware(self, name: str, is_family: bool = False) -> Malware:
        return create_malware(
            name=name,
            created_by=self.author,
            is_family=is_family,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_intrusion_sets(self) -> list[IntrusionSet]:
        report_actors = self.report.get("actors") or []
        if not report_actors:
            return []

        intrusion_sets: list[IntrusionSet] = []

        for actor in report_actors:
            try:
                actor_builder = self.related_actor_builder_cls(
                    actor=actor,
                    author=self.author,
                    source_name=self.source_name,
                    object_markings=self.object_markings,
                    confidence_level=self.confidence_level,
                )
                built = actor_builder.build()

                # Some builders may return a single IntrusionSet, others a list of IntrusionSet
                if isinstance(built, list):
                    intrusion_sets.extend(cast(list[IntrusionSet], built))
                else:
                    intrusion_sets.append(cast(IntrusionSet, built))

            except Exception:
                logger.exception(
                    "Failed to create IntrusionSet from report actor '%s'", actor
                )

        return intrusion_sets

    def _create_external_reference(
        self, external_id: str, url: str
    ) -> ExternalReference:
        return create_external_reference(self.source_name, external_id, url)

    def _create_uses_relationships(
        self, sources: Sequence[object], targets: Sequence[object]
    ) -> list[Relationship]:
        return create_uses_relationships(
            self.author,
            cast(list[_DomainObject], list(sources)),
            cast(list[_DomainObject], list(targets)),
            self.confidence_level,
            self.object_markings,
            self.start_time,
            self.stop_time,
        )

    def _create_targets_relationships(
        self, sources: Sequence[object], targets: Sequence[object]
    ) -> list[Relationship]:
        return create_targets_relationships(
            self.author,
            cast(list[_DomainObject], list(sources)),
            cast(list[_DomainObject], list(targets)),
            self.confidence_level,
            self.object_markings,
            self.start_time,
            self.stop_time,
        )

    def _create_targeted_sectors(self) -> list[Identity]:
        target_industries = self.report["target_industries"]
        if target_industries is None or not target_industries:
            return []

        return create_sectors_from_entities(target_industries, self.author)

    def _create_targeted_regions_and_countries(
        self,
    ) -> tuple[list[Location], list[Location]]:
        report_target_countries = self.report["target_countries"]
        if report_target_countries is None or not report_target_countries:
            return [], []

        return self._create_regions_and_countries_from_entities(report_target_countries)

    def _create_regions_and_countries_from_entities(
        self, entities: list
    ) -> tuple[list[Location], list[Location]]:
        return create_regions_and_countries_from_entities(entities, self.author)

    def _create_files(self) -> list[Mapping[str, str | bool]]:
        files: list[Mapping[str, str | bool]] = []
        if self.report_file is not None:
            files.append(self.report_file)
        return files

    def _create_report(self, object_refs: list[str]) -> STIXReport:
        files = self._create_files()
        return self._create_stix2_report_from_report(object_refs, files)

    def _create_stix2_report_from_report(
        self,
        object_refs: list[str],
        files: list[Mapping[str, str | bool]],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            self.report,
            self.source_name,
            self.author,
            object_refs,
            [self.report_type],
            self.confidence_level,
            self.object_markings,
            self.report_status,
            x_opencti_files=files,
        )

    def _create_dummy_object(self) -> Identity:
        return create_organization(self._DUMMY_OBJECT_NAME, self.author)

    def _normalize_report_object_refs(self, refs: Iterable[Any]) -> list[str]:
        normalized: list[str] = []
        for ref in refs or []:
            if ref is None:
                continue
            if isinstance(ref, str):
                normalized.append(ref)
                continue

            # STIX2 objects expose an .id attribute
            stix_id = getattr(ref, "id", None)
            if isinstance(stix_id, str):
                normalized.append(stix_id)
                continue

            # Dict-like objects may carry an "id" key
            if isinstance(ref, dict) and isinstance(ref.get("id"), str):
                normalized.append(ref["id"])
                continue

            logger.warning(
                "Skipping non-STIX object ref in report.object_refs (type=%s): %s",
                type(ref),
                str(ref)[:200],
            )

        # De-dupe while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for item in normalized:
            if item not in seen:
                deduped.append(item)
                seen.add(item)
        return deduped

    def build(self) -> Bundle:
        """Build report bundle."""
        # Create bundle with author.
        bundle_objects: list[object] = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets: list[IntrusionSet] = []
        if self.scopes is None or "actor" in self.scopes:
            intrusion_sets = self._create_intrusion_sets()
            bundle_objects.extend(intrusion_sets)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Create targeted countries and regions and add to bundle.
        target_regions, target_countries = self._create_targeted_regions_and_countries()
        bundle_objects.extend(target_regions)
        bundle_objects.extend(target_countries)

        intrusion_sets_use_malwares = []
        intrusion_sets_target_sectors = []
        malwares_target_sectors = []
        intrusion_sets_target_regions = []
        intrusion_sets_target_countries = []
        malwares_target_regions = []
        malwares_target_countries = []

        if self.report_guess_relations:
            intrusion_sets_use_malwares = self._create_uses_relationships(
                intrusion_sets, malwares
            )
            bundle_objects.extend(intrusion_sets_use_malwares)

            intrusion_sets_target_sectors = self._create_targets_relationships(
                intrusion_sets, target_sectors
            )
            bundle_objects.extend(intrusion_sets_target_sectors)

            malwares_target_sectors = self._create_targets_relationships(
                malwares, target_sectors
            )
            bundle_objects.extend(malwares_target_sectors)

            intrusion_sets_target_regions = self._create_targets_relationships(
                intrusion_sets, target_regions
            )
            bundle_objects.extend(intrusion_sets_target_regions)

            intrusion_sets_target_countries = self._create_targets_relationships(
                intrusion_sets, target_countries
            )
            bundle_objects.extend(intrusion_sets_target_countries)

            malwares_target_regions = self._create_targets_relationships(
                malwares, target_regions
            )
            bundle_objects.extend(malwares_target_regions)

            malwares_target_countries = self._create_targets_relationships(
                malwares, target_countries
            )
            bundle_objects.extend(malwares_target_countries)

        # Indicators linked to the report and add to bundle
        indicators_linked = self.related_indicators or []
        bundle_objects.extend(indicators_linked)

        # Create object references for the report.
        # Always include entities in object refs
        object_refs = create_object_refs(
            cast(list[_DomainObject], intrusion_sets),
            cast(list[_DomainObject], malwares),
            cast(list[_DomainObject], target_sectors),
            cast(list[_DomainObject], target_regions),
            cast(list[_DomainObject], target_countries),
        )

        # Add relationships to object refs when guessing is enabled
        if self.report_guess_relations:
            relationship_refs = create_object_refs(
                cast(list[_RelationshipObject], intrusion_sets_use_malwares),
                cast(list[_RelationshipObject], intrusion_sets_target_sectors),
                cast(list[_RelationshipObject], malwares_target_sectors),
                cast(list[_RelationshipObject], intrusion_sets_target_regions),
                cast(list[_RelationshipObject], intrusion_sets_target_countries),
                cast(list[_RelationshipObject], malwares_target_regions),
                cast(list[_RelationshipObject], malwares_target_countries),
            )
            object_refs.extend(relationship_refs)

        # TODO: Ignore reports without any references or not?
        # Hack, the report must have at least on object reference.
        if not object_refs:
            dummy_object = self._create_dummy_object()

            bundle_objects.append(dummy_object)
            object_refs.append(dummy_object.id)

        # Add related indicator to object refs for report
        object_refs.extend(indicators_linked)

        object_refs = self._normalize_report_object_refs(object_refs)
        report = self._create_report(object_refs)
        bundle_objects.append(report)

        return Bundle(objects=bundle_objects, allow_custom=True)
