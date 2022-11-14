# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike Snort master builder module."""

from datetime import date, datetime, timezone
from typing import List, Mapping

from crowdstrike_client.api.models.report import Report
from stix2 import Bundle, Identity, Indicator, MarkingDefinition
from stix2 import Report as STIXReport  # type: ignore
from stix2.v21 import _DomainObject  # type: ignore

from crowdstrike.utils import (
    create_indicator,
    create_object_refs,
    create_stix2_report_from_report,
)
from crowdstrike.utils.report_fetcher import FetchedReport
from crowdstrike.utils.snort_parser import SnortRule


class SnortRuleBundleBuilder:
    """Snort master builder."""

    _PATTERN_TYPE_Snort = "snort"

    def __init__(
        self,
        rule: SnortRule,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        confidence_level: int,
        report_status: int,
        report_type: str,
        reports: List[FetchedReport],
    ) -> None:
        """Initialize Snort master builder."""
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
        """Build Snort rule bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create indicators and add to bundle.
        indicators = self._create_indicators()
        bundle_objects.extend(indicators)

        # Create object references for the report.
        object_refs = create_object_refs(indicators)

        # Create reports and add to bundle.
        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        return Bundle(objects=bundle_objects, allow_custom=True)

    def _create_indicators(self) -> List[Indicator]:
        return [self._create_snort_indicator()]

    def _create_snort_indicator(self) -> Indicator:
        rule = self.rule

        return create_indicator(
            rule.rule,
            self._PATTERN_TYPE_Snort,
            created_by=self.author,
            name=rule.name,
            description=rule.description,
            valid_from=self.first_seen,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
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
        report: Report,
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
