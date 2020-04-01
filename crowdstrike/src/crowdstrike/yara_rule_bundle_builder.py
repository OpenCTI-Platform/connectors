# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike YARA rule bundle builder module."""

import logging
from datetime import date, datetime, timezone
from typing import List, Mapping

from crowdstrike_client.api.models.report import Report

from stix2 import (
    Bundle,
    ExternalReference,
    Identity,
    Indicator,
    IntrusionSet,
    KillChainPhase,
    Malware,
    MarkingDefinition,
    Relationship,
    Report as STIXReport,
)
from stix2.core import STIXDomainObject

from crowdstrike.report_fetcher import FetchedReport
from crowdstrike.utils import (
    create_indicates_relationships,
    create_indicator,
    create_intrusion_sets_from_names,
    create_malware,
    create_object_refs,
    create_stix2_report_from_report,
    create_uses_relationships,
)
from crowdstrike.yara_rules_parser import YaraRule

logger = logging.getLogger(__name__)


class YaraRuleBundleBuilder:
    """YARA rule bundle builder."""

    _OBSERVABLE_TYPE_UNKNOWN = "Unknown"

    _PATTERN_TYPE_YARA = "yara"

    _PATTERN_VALUE_DUMMY = "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']"

    def __init__(
        self,
        rule: YaraRule,
        author: Identity,
        source_name: str,
        object_marking_refs: List[MarkingDefinition],
        confidence_level: int,
        report_status: int,
        report_type: str,
        reports: List[FetchedReport],
    ) -> None:
        """Initialize YARA rule bundle builder."""
        self.rule = rule
        self.author = author
        self.source_name = source_name
        self.object_marking_refs = object_marking_refs
        self.confidence_level = confidence_level
        self.report_status = report_status
        self.report_type = report_type
        self.reports = reports

        self.first_seen = self._date_to_datetime(self.rule.last_modified)
        self.last_seen = self._date_to_datetime(self.rule.last_modified)

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
        bundle_objects.extend(self.object_marking_refs)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares, add to bundle.
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

        return Bundle(objects=bundle_objects)

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        external_references: List[ExternalReference] = []
        return create_intrusion_sets_from_names(
            self.rule.actors, self.author, external_references, self.object_marking_refs
        )

    def _create_malwares(self) -> List[Malware]:
        aliases: List[str] = []
        kill_chain_phases: List[KillChainPhase] = []
        external_references: List[ExternalReference] = []

        malwares = []
        for malware_family in self.rule.malware_families:
            malware = create_malware(
                malware_family,
                aliases,
                self.author,
                kill_chain_phases,
                external_references,
                self.object_marking_refs,
            )
            malwares.append(malware)
        return malwares

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

    def _create_indicators(self) -> List[Indicator]:
        return [self._create_yara_indicator()]

    def _create_yara_indicator(self) -> Indicator:
        rule = self.rule
        indicator = self._create_indicator(
            name=rule.name,
            description=rule.description,
            valid_from=self.first_seen,
            observable_type=self._OBSERVABLE_TYPE_UNKNOWN,
            observable_value=rule.rule,
            pattern_type=self._PATTERN_TYPE_YARA,
            pattern_value=self._PATTERN_VALUE_DUMMY,
            indicator_pattern=rule.rule,
        )
        return indicator

    def _create_indicator(
        self,
        name: str,
        description: str,
        valid_from: datetime,
        observable_type: str,
        observable_value: str,
        pattern_type: str,
        pattern_value: str,
        indicator_pattern: str,
    ) -> Indicator:
        kill_chain_phases: List[KillChainPhase] = []

        return create_indicator(
            name,
            description,
            self.author,
            valid_from,
            kill_chain_phases,
            observable_type,
            observable_value,
            pattern_type,
            pattern_value,
            indicator_pattern,
            self.object_marking_refs,
        )

    def _create_indicates_relationships(
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
    ) -> List[Relationship]:
        return create_indicates_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

    def _create_reports(self, object_refs: List[STIXDomainObject]) -> List[STIXReport]:
        reports = []
        for rule_report in self.reports:
            report = self._create_report(
                rule_report.report,
                self.author,
                object_refs,
                self.object_marking_refs,
                rule_report.files,
            )
            reports.append(report)
        return reports

    def _create_report(
        self,
        report: Report,
        author: Identity,
        object_refs: List[STIXDomainObject],
        object_marking_refs: List[MarkingDefinition],
        files: List[Mapping[str, str]],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            report,
            author,
            self.source_name,
            object_refs,
            object_marking_refs,
            self.report_status,
            self.report_type,
            self.confidence_level,
            files,
        )
