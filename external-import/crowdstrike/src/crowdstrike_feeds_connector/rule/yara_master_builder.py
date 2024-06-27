# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike YARA master builder module."""

from datetime import date, datetime, timezone
from typing import List, Mapping

from crowdstrike_feeds_services.utils import (
    create_indicates_relationships,
    create_indicator,
    create_intrusion_sets_from_names,
    create_malware,
    create_object_refs,
    create_stix2_report_from_report,
    create_uses_relationships,
)
from crowdstrike_feeds_services.utils.report_fetcher import FetchedReport
from crowdstrike_feeds_services.utils.yara_parser import YaraRule
from stix2 import (
    Bundle,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    MarkingDefinition,
    Relationship,
)
from stix2 import Report as STIXReport  # type: ignore
from stix2.v21 import _DomainObject  # type: ignore


class YaraRuleBundleBuilder:
    """YARA master builder."""

    _PATTERN_TYPE_YARA = "yara"

    def __init__(
        self,
        rule: YaraRule,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        confidence_level: int,
        report_status: int,
        report_type: str,
        reports: List[FetchedReport],
    ) -> None:
        """Initialize YARA master builder."""
        self.rule = rule
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.confidence_level = confidence_level
        self.report_status = report_status
        self.report_type = report_type
        self.reports = reports

        self.first_seen = self._date_to_datetime(self.rule.last_modified)

    @staticmethod
    def _date_to_datetime(input_date: date) -> datetime:
        return datetime(
            input_date.year, input_date.month, input_date.day, tzinfo=timezone.utc
        )

    def build(self) -> Bundle:
        """Build YARA rule bundle."""
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

        # Create indicators and add to bundle.
        indicators = self._create_indicators()
        bundle_objects.extend(indicators)

        # Indicator indicates entities, add to bundle.
        indicator_indicates = intrusion_sets + malwares

        indicator_indicates_entities = self._create_indicates_relationships(
            indicators, indicator_indicates
        )
        bundle_objects.extend(indicator_indicates_entities)

        # Create object references for the report.
        object_refs = create_object_refs(
            intrusion_sets,
            malwares,
            intrusion_sets_use_malwares,
            indicators,
            indicator_indicates_entities,
        )

        # Create reports and add to bundle.
        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        return Bundle(objects=bundle_objects, allow_custom=True)

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        rule_actors = self.rule.actors

        return create_intrusion_sets_from_names(
            rule_actors,
            created_by=self.author,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_malwares(self) -> List[Malware]:
        malwares = []
        for malware_family in self.rule.malware_families:
            malware = self._create_malware(malware_family)
            malwares.append(malware)
        return malwares

    def _create_malware(self, name: str) -> Malware:
        return create_malware(
            name,
            created_by=self.author,
            is_family=True,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_uses_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
        )

    def _create_indicators(self) -> List[Indicator]:
        return [self._create_yara_indicator()]

    def _create_yara_indicator(self) -> Indicator:
        rule = self.rule

        return create_indicator(
            rule.rule,
            self._PATTERN_TYPE_YARA,
            created_by=self.author,
            name=rule.name,
            description=rule.description,
            valid_from=self.first_seen,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_indicates_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_indicates_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
        )

    def _create_reports(self, objects: List[_DomainObject]) -> List[STIXReport]:
        reports = []

        for rule_report in self.reports:
            report = self._create_report(
                rule_report.report,
                objects,
                rule_report.files,
            )
            reports.append(report)

        return reports

    def _create_report(
        self,
        report: dict,
        objects: List[_DomainObject],
        files: List[Mapping[str, str]],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            report,
            self.source_name,
            self.author,
            objects,
            [self.report_type],
            self.confidence_level,
            self.object_markings,
            self.report_status,
            x_opencti_files=files,
        )
