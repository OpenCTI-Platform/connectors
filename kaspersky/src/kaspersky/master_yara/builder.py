"""Kaspersky Master YARA builder module."""

import logging
from typing import List, Optional, Union

from stix2 import Bundle, Identity, Indicator, MarkingDefinition, Report  # type: ignore
from stix2.v21 import _DomainObject, _RelationshipObject  # type: ignore

from kaspersky.models import YaraRule
from kaspersky.utils import (
    create_object_refs,
    create_report,
    create_yara_indicator,
    datetime_utc_now,
)


log = logging.getLogger(__name__)


class YaraRuleGroupBundleBuilder:
    """Kaspersky YARA rule group bundle builder."""

    def __init__(
        self,
        yara_rule_group: str,
        group_yara_rules: List[YaraRule],
        author: Identity,
        object_markings: List[MarkingDefinition],
        source_name: str,
        confidence_level: int,
        include_report: bool,
        report_type: str,
        report_status: int,
    ) -> None:
        """Initialize Kaspersky YARA rule group bundle builder."""
        self.yara_rule_group = yara_rule_group
        self.group_yara_rules = group_yara_rules
        self.author = author
        self.object_markings = object_markings
        self.source_name = source_name
        self.confidence_level = confidence_level
        self.include_report = include_report
        self.report_type = report_type
        self.report_status = report_status

    def build(self) -> Optional[Bundle]:
        """Build Kaspersky YARA rule group bundle."""
        # Prepare STIX2 bundle objects with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create indicators and add to bundle.
        indicators = self._create_indicators()
        if not indicators:
            log.warning("No indicators for YARA rule group '%s'", self.yara_rule_group)
            return None

        bundle_objects.extend(indicators)

        if self.include_report:
            # Create object references for the report.
            objects = create_object_refs(indicators)

            # Create report and add to bundle.
            report = self._create_report(objects)
            if report is not None:
                bundle_objects.append(report)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        return Bundle(objects=bundle_objects, allow_custom=True)

    def _create_indicators(self) -> List[Indicator]:
        indicators = []

        for yara_rule in self.group_yara_rules:
            indicator = self._create_yara_indicator(yara_rule)
            if indicator is not None:
                indicators.append(indicator)

        return indicators

    def _create_yara_indicator(self, yara_rule: YaraRule) -> Optional[Indicator]:
        created_by = self.author
        modified = datetime_utc_now()
        object_markings = self.object_markings
        confidence_level = self.confidence_level

        return create_yara_indicator(
            yara_rule,
            created_by=created_by,
            modified=modified,
            confidence=confidence_level,
            object_markings=object_markings,
        )

    def _create_report(
        self, objects: List[Union[_DomainObject, _RelationshipObject]]
    ) -> Optional[Report]:
        name = self.yara_rule_group
        if name is None or not name:
            return None

        published = datetime_utc_now()

        created_by = self.author
        object_markings = self.object_markings
        confidence_level = self.confidence_level
        report_type = self.report_type
        report_status = self.report_status

        return create_report(
            name,
            published,
            objects,
            created_by=created_by,
            report_types=[report_type],
            confidence=confidence_level,
            object_markings=object_markings,
            x_opencti_report_status=report_status,
        )
