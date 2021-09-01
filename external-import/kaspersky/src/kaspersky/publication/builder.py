"""Kaspersky publication builder module."""

import logging
from datetime import datetime
from typing import List, Mapping, Optional, Set, Union

from stix2 import (  # type: ignore
    Bundle,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    MarkingDefinition,
    Relationship,
    Report,
)
from stix2.v21 import _DomainObject, _RelationshipObject  # type: ignore

from kaspersky.models import OpenIOC, OpenIOCIndicatorItem, Publication, Yara, YaraRule
from kaspersky.utils import (
    Observation,
    ObservationConfig,
    ObservationFactory,
    convert_openioc_xml_to_openioc_model,
    convert_yara_rules_to_yara_model,
    create_country,
    create_file_pdf,
    create_indicates_relationships,
    create_intrusion_set,
    create_object_refs,
    create_organization,
    create_region,
    create_report,
    create_sector,
    create_targets_relationships,
    create_yara_indicator,
    decode_base64_gzip_to_bytes,
    decode_base64_gzip_to_string,
    get_observation_factory_by_openioc_search,
)


log = logging.getLogger(__name__)


class PublicationBundleBuilder:
    """Kaspersky publication bundle builder."""

    _DUMMY_OBJECT_NAME = "KASPERSKY EMPTY REPORT"

    def __init__(
        self,
        publication: Publication,
        author: Identity,
        source_name: str,
        object_markings: List[MarkingDefinition],
        create_observables: bool,
        create_indicators: bool,
        confidence_level: int,
        report_type: str,
        report_status: int,
        excluded_ioc_indicator_types: Set[str],
        opencti_regions: Set[str],
    ) -> None:
        """Initialize Kaspersky publication bundle builder."""
        self.publication = publication
        self.author = author
        self.source_name = source_name
        self.object_markings = object_markings
        self.create_observables = create_observables
        self.create_indicators = create_indicators
        self.confidence_level = confidence_level
        self.report_type = report_type
        self.report_status = report_status
        self.excluded_ioc_indicator_types = excluded_ioc_indicator_types
        self.opencti_regions = opencti_regions

    def build(self) -> Optional[Bundle]:
        """Build Kaspersky publication bundle."""
        # Prepare STIX2 bundle objects with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create sectors and add to bundle.
        sectors = self._create_sectors()
        bundle_objects.extend(sectors)

        # Intrusion sets target sectors and add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Create locations and add to bundle.
        locations = self._create_locations()
        bundle_objects.extend(locations)

        # Intrusion sets target locations and add to bundle.
        intrusion_sets_target_locations = self._create_targets_relationships(
            intrusion_sets, locations
        )
        bundle_objects.extend(intrusion_sets_target_locations)

        # Create observations.
        observations = self._create_ioc_observations()

        # Get observables and add to bundle.
        observables = [o.observable for o in observations if o.observable is not None]
        bundle_objects.extend(observables)

        # Get indicators, create YARA indicators and to bundle.
        indicators = [o.indicator for o in observations if o.indicator is not None]
        indicators.extend(self._create_yara_indicators())
        bundle_objects.extend(indicators)

        # Get observation relationships and add to bundle.
        indicators_based_on_observables = [
            o.relationship for o in observations if o.relationship is not None
        ]
        bundle_objects.extend(indicators_based_on_observables)

        # Indicator indicates entities, add to bundle.
        indicator_indicates = intrusion_sets

        indicator_indicates_entities = self._create_indicates_relationships(
            indicators, indicator_indicates
        )
        bundle_objects.extend(indicator_indicates_entities)

        # Create object references for the report.
        object_refs = create_object_refs(
            intrusion_sets,
            sectors,
            intrusion_sets_target_sectors,
            locations,
            intrusion_sets_target_locations,
            observables,
            indicators,
            indicators_based_on_observables,
            indicator_indicates_entities,
        )

        # TODO: Ignore reports without any references or not?
        # Hack, the report must have at least on object reference.
        if not object_refs:
            dummy_object = self._create_dummy_object()

            bundle_objects.append(dummy_object)
            object_refs.append(dummy_object)

        # Create report and add to bundle.
        report = self._create_report(object_refs)
        bundle_objects.append(report)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        return Bundle(objects=bundle_objects, allow_custom=True)

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        intrusion_sets = []

        tags_actors = self.publication.tags_actors
        for tag in tags_actors:
            if not tag:
                continue

            intrusion_set = self._create_intrusion_set(tag)
            intrusion_sets.append(intrusion_set)

        return intrusion_sets

    def _create_intrusion_set(self, name: str) -> IntrusionSet:
        create_by = self.author
        object_markings = self.object_markings
        confidence = self.confidence_level

        return create_intrusion_set(
            name,
            created_by=create_by,
            confidence=confidence,
            object_markings=object_markings,
        )

    def _create_sectors(self) -> List[Identity]:
        sectors = []

        tags_industry = self.publication.tags_industry
        for tag in tags_industry:
            if not tag:
                continue

            sector = self._create_sector(tag)
            sectors.append(sector)

        return sectors

    def _create_sector(self, name: str) -> Identity:
        created_by = self.author

        return create_sector(name, created_by=created_by)

    def _create_targets_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        created_by = self.author
        object_markings = self.object_markings
        confidence_level = self.confidence_level
        start_time = self.publication.published

        return create_targets_relationships(
            created_by,
            sources,
            targets,
            confidence_level,
            object_markings,
            start_time=start_time,
        )

    def _create_locations(self) -> List[Location]:
        locations = []

        tags_geo = self.publication.tags_geo
        for tag in tags_geo:
            if not tag:
                continue

            if tag in self.opencti_regions:
                location = self._create_region(tag)
            else:
                location = self._create_country(tag)

            locations.append(location)

        return locations

    def _create_region(self, name: str) -> Location:
        created_by = self.author

        return create_region(name, created_by=created_by)

    def _create_country(self, name: str) -> Location:
        created_by = self.author

        return create_country(name, created_by=created_by)

    def _create_dummy_object(self) -> Identity:
        created_by = self.author

        return create_organization(self._DUMMY_OBJECT_NAME, created_by=created_by)

    def _create_report(
        self, objects: List[Union[_DomainObject, _RelationshipObject]]
    ) -> Report:
        created_by = self.author
        object_markings = self.object_markings
        confidence_level = self.confidence_level
        report_type = self.report_type
        report_status = self.report_status

        name = self.publication.name
        description = self.publication.desc
        created = self.publication.published
        modified = self.publication.updated

        labels = self._get_labels()
        files = self._create_files()

        return create_report(
            name,
            created,
            objects,
            created_by=created_by,
            created=created,
            modified=modified,
            description=description,
            report_types=[report_type],
            labels=labels,
            confidence=confidence_level,
            object_markings=object_markings,
            x_opencti_report_status=report_status,
            x_opencti_files=files,
        )

    def _get_labels(self) -> List[str]:
        labels = []

        tags = self.publication.tags
        for tag in tags:
            if not tag:
                continue

            labels.append(tag)

        return labels

    def _create_files(self) -> Optional[List[Mapping[str, str]]]:
        report_file = self._create_file()
        if report_file is None:
            return None

        return [report_file]

    def _create_file(self) -> Optional[Mapping[str, str]]:
        report_pdf = self.publication.report_pdf
        if report_pdf is None:
            return None

        report_pdf_name = f"report_{self.publication.id}.pdf"
        report_pdf_bytes = decode_base64_gzip_to_bytes(report_pdf)

        return create_file_pdf(report_pdf_name, report_pdf_bytes)

    def _create_ioc_observations(self) -> List[Observation]:
        if not (self.create_observables or self.create_indicators):
            return []

        openioc = self._get_openioc()
        if openioc is None:
            return []

        description = openioc.description
        created = openioc.authored_date
        modified = openioc.last_modified

        observations = []

        indicator_items = openioc.indicator_items
        indicator_items = self._filter_excluded_indicator_types(indicator_items)

        for indicator_item in indicator_items:
            observation = self._create_ioc_observation(
                indicator_item, description, created, modified
            )
            if observation is None:
                continue

            observations.append(observation)

        return observations

    def _get_openioc(self) -> Optional[OpenIOC]:
        report_iocs = self.publication.report_iocs
        if report_iocs is None:
            return None

        report_iocs_bytes = decode_base64_gzip_to_bytes(report_iocs)
        return convert_openioc_xml_to_openioc_model(report_iocs_bytes)

    def _filter_excluded_indicator_types(
        self, indicator_items: List[OpenIOCIndicatorItem]
    ) -> List[OpenIOCIndicatorItem]:
        excluded_types = self.excluded_ioc_indicator_types

        def _exclude_indicator_types_filter(
            indicator_item: OpenIOCIndicatorItem,
        ) -> bool:
            context_search = indicator_item.context_search
            if context_search is None:
                log.warning("Excluding OpenIOC indicator item with no context search")
                return False

            split_context_search = context_search.split("/")
            last_value = split_context_search[-1]

            if context_search in excluded_types or last_value in excluded_types:
                log.info(
                    "Excluding OpenIOC indicator item '%s' (%s)",
                    indicator_item.content_text,
                    context_search,
                )
                return False
            else:
                return True

        return list(filter(_exclude_indicator_types_filter, indicator_items))

    def _create_ioc_observation(
        self,
        indicator_item: OpenIOCIndicatorItem,
        description: Optional[str],
        created: Optional[datetime],
        modified: Optional[datetime],
    ) -> Optional[Observation]:
        if not (self.create_observables or self.create_indicators):
            return None

        item_id = indicator_item.id
        item_search = indicator_item.context_search
        item_content = indicator_item.content_text
        item_content_type = indicator_item.content_type

        if not (item_id and item_search and item_content and item_content_type):
            log.error("Unable to create IOC observation from '%s'", indicator_item)
            return None

        factory = self._get_observation_factory(item_search)
        if factory is None:
            return None

        observation_config = ObservationConfig(
            value=item_content,
            description=description,
            created_by=self.author,
            labels=self._get_labels(),
            confidence=self.confidence_level,
            object_markings=self.object_markings,
            created=created,
            modified=modified,
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
        )

        return factory.create(observation_config)

    @staticmethod
    def _get_observation_factory(item_search: str) -> Optional[ObservationFactory]:
        observation_factory = get_observation_factory_by_openioc_search(item_search)
        if observation_factory is None:
            log.warning("No observation factory for '%s'", item_search)
            return None

        return observation_factory

    def _create_yara_indicators(self) -> List[Indicator]:
        if not self.create_indicators:
            return []

        if (
            "Yara/Yara" in self.excluded_ioc_indicator_types
            or "Yara" in self.excluded_ioc_indicator_types
        ):
            log.info("Excluding Yara indicators")
            return []

        yara = self._get_yara()
        if yara is None:
            return []

        created = self.publication.published
        modified = self.publication.updated

        indicators = []

        yara_rules = yara.rules
        for yara_rule in yara_rules:
            indicator = self._create_yara_indicator(yara_rule, created, modified)
            indicators.append(indicator)

        return indicators

    def _get_yara(self) -> Optional[Yara]:
        report_yara = self.publication.report_yara
        if report_yara is None:
            return None

        report_yara_bytes = decode_base64_gzip_to_string(report_yara)
        return convert_yara_rules_to_yara_model(report_yara_bytes)

    def _create_yara_indicator(
        self, yara_rule: YaraRule, created: datetime, modified: datetime
    ) -> Indicator:
        created_by = self.author
        object_markings = self.object_markings
        labels = self._get_labels()
        confidence_level = self.confidence_level

        return create_yara_indicator(
            yara_rule,
            created_by=created_by,
            created=created,
            modified=modified,
            labels=labels,
            confidence=confidence_level,
            object_markings=object_markings,
        )

    def _create_indicates_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        created_by = self.author
        object_markings = self.object_markings
        confidence_level = self.confidence_level
        start_time = self.publication.published

        return create_indicates_relationships(
            created_by,
            sources,
            targets,
            confidence_level,
            object_markings,
            start_time=start_time,
        )
