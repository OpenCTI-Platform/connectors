"""Kaspersky Master IOC builder module."""

import logging
from typing import List, Optional, Union

from kaspersky.models import OpenIOCCSVIndicator
from kaspersky.utils import (
    Observation,
    ObservationConfig,
    ObservationFactory,
    create_object_refs,
    create_report,
    get_observation_factory_by_openioc_indicator_type,
)
from stix2 import Bundle, Identity, MarkingDefinition, Report  # type: ignore
from stix2.v21 import _DomainObject, _RelationshipObject  # type: ignore

log = logging.getLogger(__name__)


class IndicatorGroupBundleBuilder:
    """Kaspersky indicator group bundle builder."""

    def __init__(
        self,
        indicator_group: str,
        group_indicators: List[OpenIOCCSVIndicator],
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        create_observables: bool,
        create_indicators: bool,
        confidence_level: int,
        report_type: str,
        report_status: int,
    ) -> None:
        """Initialize Kaspersky indicator group bundle builder."""
        self.indicator_group = indicator_group
        self.group_indicators = group_indicators
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.create_observables = create_observables
        self.create_indicators = create_indicators
        self.confidence_level = confidence_level
        self.report_type = report_type
        self.report_status = report_status

    def build(self) -> Optional[Bundle]:
        """Build Kaspersky indicator group bundle."""
        # Prepare STIX2 bundle objects with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create observations.
        observations = self._create_ioc_observations()
        if not observations:
            log.error("No indicators nor observables for %s", self.indicator_group)
            return None

        # Get observables and add to bundle.
        observables = [o.observable for o in observations if o.observable is not None]
        bundle_objects.extend(observables)

        # Get indicators and to bundle.
        indicators = [o.indicator for o in observations if o.indicator is not None]
        bundle_objects.extend(indicators)

        # Get observation relationships and add to bundle.
        indicators_based_on_observables = [
            o.relationship for o in observations if o.relationship is not None
        ]
        bundle_objects.extend(indicators_based_on_observables)

        # Create object references for the report.
        object_refs = create_object_refs(
            observables, indicators, indicators_based_on_observables
        )

        # Create report and add to bundle.
        report = self._create_report(object_refs)
        bundle_objects.append(report)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        return Bundle(objects=bundle_objects, allow_custom=True)

    def _create_ioc_observations(self) -> List[Observation]:
        if not (self.create_observables or self.create_indicators):
            return []

        observations = []

        for group_indicator in self.group_indicators:
            observation = self._create_ioc_observation(group_indicator)
            if observation is None:
                continue

            observations.append(observation)

        return observations

    def _create_ioc_observation(
        self, indicator: OpenIOCCSVIndicator
    ) -> Optional[Observation]:
        if not (self.create_observables or self.create_indicators):
            return None

        indicator_type = indicator.indicator_type
        indicator_content = indicator.indicator
        indicator_description = indicator.publication
        indicator_detection_date = indicator.detection_date

        factory = self._get_observation_factory(indicator_type)
        if factory is None:
            return None

        observation_config = ObservationConfig(
            value=indicator_content,
            description=indicator_description,
            created_by=self.author,
            labels=[],
            confidence=self.confidence_level,
            object_markings=self.object_markings,
            created=indicator_detection_date,
            modified=indicator_detection_date,
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
        )

        return factory.create(observation_config)

    @staticmethod
    def _get_observation_factory(indicator_type: str) -> Optional[ObservationFactory]:
        observation_factory = get_observation_factory_by_openioc_indicator_type(
            indicator_type
        )
        if observation_factory is None:
            log.warning("No observation factory for '%s'", indicator_type)
            return None

        return observation_factory

    def _create_report(
        self, objects: List[Union[_DomainObject, _RelationshipObject]]
    ) -> Report:
        created_by = self.author
        object_markings = self.object_markings
        confidence_level = self.confidence_level
        report_type = self.report_type
        report_status = self.report_status

        name = self.indicator_group
        created = self.group_indicators[0].detection_date
        modified = created

        return create_report(
            name,
            created,
            objects,
            created_by=created_by,
            created=created,
            modified=modified,
            report_types=[report_type],
            confidence=confidence_level,
            object_markings=object_markings,
            x_opencti_report_status=report_status,
        )
