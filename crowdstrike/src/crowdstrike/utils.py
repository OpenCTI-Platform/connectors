# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector utilities module."""

import base64
import calendar
import functools
import logging
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Mapping,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

from crowdstrike_client.api.models import Response
from crowdstrike_client.api.models.download import Download
from crowdstrike_client.api.models.report import Actor, Entity, Report

from lxml.html import fromstring

from stix2 import (
    EqualityComparisonExpression,
    ExternalReference,
    Identity,
    Location,
    Indicator as STIXIndicator,
    IntrusionSet,
    KillChainPhase,
    Malware,
    MarkingDefinition,
    ObjectPath,
    ObservationExpression,
    Relationship,
    Report as STIXReport,
    StringConstant,
    Vulnerability,
)
from stix2.v20 import _DomainObject, _RelationshipObject


logger = logging.getLogger(__name__)


T = TypeVar("T")


def paginate(
    func: Callable[..., Response[T]]
) -> Callable[..., Generator[List[T], None, None]]:
    """Paginate API calls."""

    @functools.wraps(func)
    def wrapper_paginate(
        *args: Any, limit: int = 25, **kwargs: Any
    ) -> Generator[List[T], None, None]:
        logger.info(
            "func: %s, limit: %s, args: %s, kwargs: %s",
            func.__name__,
            limit,
            args,
            kwargs,
        )

        total_count = 0

        _limit = limit
        _offset = 0
        _total = None

        while next_batch(_limit, _offset, _total):
            response = func(*args, limit=_limit, offset=_offset, **kwargs)

            errors = response.errors
            if errors:
                logger.error("Query completed with errors")
                for error in errors:
                    logger.error("Error: %s (code: %s)", error.message, error.code)

            meta = response.meta
            if meta.pagination is not None:
                pagination = meta.pagination

                _meta_limit = pagination.limit
                _meta_offset = pagination.offset
                _meta_total = pagination.total

                logger.info(
                    "Query pagination info limit: %s, offset: %s, total: %s",
                    _meta_limit,
                    _meta_offset,
                    _meta_total,
                )

                _offset = _offset + _limit
                _total = _meta_total

            resources = response.resources
            resources_count = len(resources)

            logger.info("Query fetched %s resources", resources_count)

            total_count += resources_count

            yield resources

        logger.info("Fetched %s resources in total", total_count)

    return wrapper_paginate


def next_batch(limit: int, offset: int, total: Optional[int]) -> bool:
    """Is there a next batch of resources?"""
    if total is None:
        return True
    return (total - offset) > 0


def datetime_to_timestamp(datetime_value: datetime) -> int:
    # Use calendar.timegm because the time.mktime assumes that the input is in your
    # local timezone.
    return calendar.timegm(datetime_value.timetuple())


def timestamp_to_datetime(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_utc_epoch_start() -> datetime:
    return timestamp_to_datetime(0)


def create_external_reference(
    source_name: str, external_id: str, url: str
) -> ExternalReference:
    """Create an external reference."""
    return ExternalReference(source_name=source_name, external_id=external_id, url=url)


def create_vulnerability(
    name: str,
    author: Identity,
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> Vulnerability:
    """Create a vulnerability."""
    return Vulnerability(
        created_by_ref=author,
        name=name,
        labels=["vulnerability"],
        external_references=external_references,
        object_marking_refs=object_marking_refs,
    )


def create_malware(
    name: str,
    aliases: List[str],
    author: Identity,
    kill_chain_phases: List[KillChainPhase],
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
    malware_id: Optional[str] = None,
) -> Malware:
    """Create a malware."""
    return Malware(
        id=malware_id,
        created_by_ref=author,
        name=name,
        aliases=aliases,
        kill_chain_phases=kill_chain_phases,
        labels=["malware"],
        external_references=external_references,
        object_marking_refs=object_marking_refs,
    )


def create_kill_chain_phase(kill_chain_name: str, phase_name: str) -> KillChainPhase:
    """Create a kill chain phase."""
    return KillChainPhase(kill_chain_name=kill_chain_name, phase_name=phase_name)


def create_intrusion_set(
    name: str,
    aliases: List[str],
    author: Identity,
    primary_motivation: Optional[str],
    secondary_motivations: List[str],
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> IntrusionSet:
    """Create an intrusion set."""
    return IntrusionSet(
        created_by_ref=author,
        name=name,
        aliases=aliases,
        primary_motivation=primary_motivation,
        secondary_motivations=secondary_motivations,
        labels=["intrusion-set"],
        external_references=external_references,
        object_marking_refs=object_marking_refs,
    )


def create_intrusion_set_from_actor(
    actor: Actor,
    author: Identity,
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> IntrusionSet:
    """Create an intrusion set from actor model."""
    name = actor.name
    if name is None:
        name = f"NO_NAME_{actor.id}"

    return create_intrusion_set_from_name(
        name, author, external_references, object_marking_refs
    )


def create_intrusion_sets_from_names(
    names: List[str],
    author: Identity,
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> List[IntrusionSet]:
    """Create intrusion sets with given names."""
    intrusion_sets = []

    for name in names:
        intrusion_set = create_intrusion_set_from_name(
            name, author, external_references, object_marking_refs
        )

        intrusion_sets.append(intrusion_set)

    return intrusion_sets


def create_intrusion_set_from_name(
    name: str,
    author: Identity,
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> IntrusionSet:
    """Create intrusion set with given name."""
    aliases: List[str] = []

    alias = name.replace(" ", "")
    if alias != name:
        aliases.append(alias)

    primary_motivation = None
    secondary_motivations: List[str] = []

    return create_intrusion_set(
        name,
        aliases,
        author,
        primary_motivation,
        secondary_motivations,
        external_references,
        object_marking_refs,
    )


def create_organization(name: str, author: Optional[Identity] = None) -> Identity:
    """Create an organization."""
    return Identity(
        created_by_ref=author,
        name=name,
        identity_class="organization",
    )


def create_sector(name: str, author: Identity) -> Identity:
    """Create a sector."""
    return Identity(
        created_by_ref=author,
        name=name,
        identity_class="class",
    )


def create_sector_from_entity(entity: Entity, author: Identity) -> Optional[Identity]:
    """Create a sector from entity."""
    sector_name = entity.value
    if sector_name is None or not sector_name:
        return None
    return create_sector(sector_name, author)


def create_sectors_from_entities(
    entities: List[Entity], author: Identity
) -> List[Identity]:
    """Create sectors from entities."""
    sectors = []
    for entity in entities:
        sector = create_sector_from_entity(entity, author)
        if sector is None:
            continue
        sectors.append(sector)
    return sectors


def create_region(entity: Entity, author: Identity) -> Identity:
    """Create a region"""
    custom_properties: Dict[str, Any] = {"x_opencti_location_type": "Region"}

    return Location(
        created_by_ref=author,
        name=entity.value,
        region=entity.value,
        custom_properties=custom_properties,
    )


def create_country(entity: Entity, author: Identity) -> Identity:
    """Create a country"""
    custom_properties: Dict[str, Any] = {"x_opencti_location_type": "Country"}

    if entity.slug is not None:
        custom_properties["x_opencti_aliases"] = [entity.slug.upper()]

    return Identity(
        created_by_ref=author,
        name=entity.value,
        country=entity.slug.upper(),
        custom_properties=custom_properties,
    )


def create_relationship(
    relationship_type: str,
    author: Identity,
    source: _DomainObject,
    target: _DomainObject,
    object_marking_refs: List[MarkingDefinition],
    start_time: datetime,
    stop_time: datetime,
    confidence_level: int,
) -> Relationship:
    """Create a relationship."""
    return Relationship(
        created_by_ref=author,
        relationship_type=relationship_type,
        source_ref=source.id,
        target_ref=target.id,
        object_marking_refs=object_marking_refs,
        start_time=start_time,
        stop_time=stop_time,
        confidence=confidence_level,
    )


def create_relationships(
    relationship_type: str,
    author: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    object_marking_refs: List[MarkingDefinition],
    start_time: datetime,
    stop_time: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create relationships."""
    relationships = []
    for source in sources:
        for target in targets:
            relationship = create_relationship(
                relationship_type,
                author,
                source,
                target,
                object_marking_refs,
                start_time,
                stop_time,
                confidence_level,
            )
            relationships.append(relationship)
    return relationships


def create_targets_relationships(
    author: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    object_marking_refs: List[MarkingDefinition],
    start_time: datetime,
    stop_time: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'targets' relationships."""
    return create_relationships(
        "targets",
        author,
        sources,
        targets,
        object_marking_refs,
        start_time,
        stop_time,
        confidence_level,
    )


def create_uses_relationships(
    author: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    object_marking_refs: List[MarkingDefinition],
    start_time: datetime,
    stop_time: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'uses' relationships."""
    return create_relationships(
        "uses",
        author,
        sources,
        targets,
        object_marking_refs,
        start_time,
        stop_time,
        confidence_level,
    )


def create_indicates_relationships(
    author: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    object_marking_refs: List[MarkingDefinition],
    start_time: datetime,
    stop_time: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'indicates' relationships."""
    return create_relationships(
        "indicates",
        author,
        sources,
        targets,
        object_marking_refs,
        start_time,
        stop_time,
        confidence_level,
    )


def create_object_refs(
    *objects: Union[
        _DomainObject,
        _RelationshipObject,
        List[_RelationshipObject],
        List[_DomainObject],
    ]
) -> List[Union[_DomainObject, _RelationshipObject]]:
    """Create object references."""
    object_refs = []
    for obj in objects:
        if not isinstance(obj, list):
            object_refs.append(obj)
        else:
            object_refs.extend(obj)
    return object_refs


def create_tag(entity: Entity, source_name: str, color: str) -> Mapping[str, str]:
    """Create a tag."""
    value = entity.value
    if value is None:
        value = f"NO_VALUE_{entity.id}"

    return {"tag_type": source_name, "value": value, "color": color}


def create_tags(entities: List[Entity], source_name: str) -> List[Mapping[str, str]]:
    """Create tags."""
    color = "#cf3217"

    tags = []
    for entity in entities:
        tag = create_tag(entity, source_name, color)
        tags.append(tag)
    return tags


def remove_html_tags(html_text: str) -> str:
    document = fromstring(html_text)
    text = document.text_content()
    return text.strip()


def create_report(
    name: str,
    description: str,
    published: datetime,
    author: Identity,
    object_refs: List[_DomainObject],
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
    report_status: int,
    report_type: str,
    confidence_level: int,
    labels: List[str],
    files: List[Mapping[str, str]],
) -> STIXReport:
    """Create a report."""
    return STIXReport(
        created_by_ref=author,
        name=name,
        description=description,
        published=published,
        object_refs=object_refs,
        labels=labels,
        external_references=external_references,
        object_marking_refs=object_marking_refs,
        confidence=confidence_level,
        report_types=[report_type],
        custom_properties={
            "x_opencti_report_status": report_status,
            "x_opencti_files": files,
        },
    )


def create_stix2_report_from_report(
    report: Report,
    author: Identity,
    source_name: str,
    object_refs: List[_DomainObject],
    object_marking_refs: List[MarkingDefinition],
    report_status: int,
    report_type: str,
    confidence_level: int,
    files: List[Mapping[str, str]],
) -> STIXReport:
    external_references = []
    report_url = report.url
    if report_url is not None and report_url:
        external_reference = create_external_reference(
            source_name, str(report.id), report_url
        )
        external_references.append(external_reference)

    tags = []
    report_tags = report.tags
    if report_tags is not None:
        tags = create_tags(report_tags, source_name)

    if report.rich_text_description is not None:
        description = remove_html_tags(report.rich_text_description)
    elif report.description is not None:
        description = report.description
    elif report.short_description is not None:
        description = report.short_description
    else:
        description = "N/A"

    report_created_date = report.created_date
    if report_created_date is None:
        report_created_date = datetime_utc_now()

    return create_report(
        report.name,
        description,
        report_created_date,
        author,
        object_refs,
        external_references,
        object_marking_refs,
        report_status,
        report_type,
        confidence_level,
        tags,
        files,
    )


def split_countries_and_regions(
    entities: List[Entity], author: Identity
) -> Tuple[List[Identity], List[Identity]]:
    target_regions = []
    target_countries = []

    for entity in entities:
        if entity.slug is None or entity.value is None:
            continue

        # Target countries may also contain regions.
        # Use hack to differentiate between countries and regions.
        if len(entity.slug) > 2:
            target_region = create_region(entity, author)
            target_regions.append(target_region)
        else:
            target_country = create_country(entity, author)
            target_countries.append(target_country)

    return target_regions, target_countries


def create_file_from_download(download: Download) -> Mapping[str, str]:
    """Create file mapping from Download model."""
    filename = download.filename
    if filename is None or not filename:
        logger.error("File download missing a filename")
        filename = "DOWNLOAD_MISSING_FILENAME"

    base64_data = base64.b64encode(download.content.read())

    return {
        "name": filename,
        "data": base64_data.decode("utf-8"),
        "mime_type": "application/pdf",
    }


def convert_comma_separated_str_to_list(input_str: str, trim: bool = True) -> List[str]:
    """Convert comma separated string to list of strings."""
    comma_separated_str = input_str.strip() if trim else input_str
    if not comma_separated_str:
        return []

    result = []
    for part_str in comma_separated_str.split(","):
        value = part_str
        if trim:
            value = value.strip()
        if not value:
            continue
        result.append(value)
    return result


def create_object_path(object_type: str, property_path: List[str]) -> ObjectPath:
    """Create pattern operand object (property) path."""
    return ObjectPath(object_type, property_path)


def create_equality_observation_expression_str(
    object_path: ObjectPath, value: str
) -> str:
    """Create observation expression string with pattern equality comparison expression."""  # noqa: E501
    operand = EqualityComparisonExpression(object_path, StringConstant(value))
    observation_expression = ObservationExpression(str(operand))
    return str(observation_expression)


def create_indicator(
    name: str,
    description: str,
    author: Identity,
    valid_from: datetime,
    kill_chain_phases: List[KillChainPhase],
    observable_type: str,
    observable_value: str,
    pattern_type: str,
    pattern_value: str,
    indicator_pattern: str,
    object_marking_refs: List[MarkingDefinition],
) -> STIXIndicator:
    """Create an indicator."""
    return STIXIndicator(
        created_by_ref=author,
        name=name,
        description=description,
        pattern=pattern_value,
        valid_from=valid_from,
        kill_chain_phases=kill_chain_phases,
        labels=["malicious-activity"],
        object_marking_refs=object_marking_refs,
        pattern_type=pattern_type,
        custom_properties={
            "x_opencti_main_observable_type": observable_type,
        },
    )
