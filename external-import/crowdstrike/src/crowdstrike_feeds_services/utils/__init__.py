# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector utilities module."""

import base64
import calendar
import functools
import logging
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

import stix2
from lxml.html import fromstring  # type: ignore
from pycti import Identity, Indicator, IntrusionSet, Location, Malware
from pycti import Report as PyCTIReport
from pycti import StixCoreRelationship, Vulnerability
from pycti.utils.constants import LocationTypes  # type: ignore
from stix2.v21 import _DomainObject, _Observable, _RelationshipObject  # type: ignore

from .constants import (
    DEFAULT_X_OPENCTI_SCORE,
    TLP_MARKING_DEFINITION_MAPPING,
    X_OPENCTI_ALIASES,
    X_OPENCTI_FILES,
    X_OPENCTI_LOCATION_TYPE,
    X_OPENCTI_MAIN_OBSERVABLE_TYPE,
    X_OPENCTI_REPORT_STATUS,
    X_OPENCTI_SCORE,
    T,
)
from .indicators import (
    IndicatorPattern,
    create_indicator_pattern_cryptocurrency_wallet,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_email_address,
    create_indicator_pattern_email_message_subject,
    create_indicator_pattern_file_md5,
    create_indicator_pattern_file_name,
    create_indicator_pattern_file_sha1,
    create_indicator_pattern_file_sha256,
    create_indicator_pattern_hostname,
    create_indicator_pattern_ipv4_address,
    create_indicator_pattern_ipv6_address,
    create_indicator_pattern_mutex,
    create_indicator_pattern_url,
    create_indicator_pattern_user_agent,
    create_indicator_pattern_windows_service_name,
    create_indicator_pattern_x509_certificate_serial_number,
    create_indicator_pattern_x509_certificate_subject,
)
from .observables import (
    ObservableProperties,
    create_observable_cryptocurrency_wallet,
    create_observable_domain_name,
    create_observable_email_address,
    create_observable_email_message_subject,
    create_observable_file_md5,
    create_observable_file_name,
    create_observable_file_sha1,
    create_observable_file_sha256,
    create_observable_hostname,
    create_observable_ipv4_address,
    create_observable_ipv6_address,
    create_observable_mutex,
    create_observable_url,
    create_observable_user_agent,
    create_observable_windows_service_name,
    create_observable_x509_certificate_serial_number,
    create_observable_x509_certificate_subject,
)

logger = logging.getLogger(__name__)


class ObservationFactory(NamedTuple):
    """Observation factory."""

    create_observable: Callable[[ObservableProperties], _Observable]
    create_indicator_pattern: Callable[[str], IndicatorPattern]


OBSERVATION_FACTORY_IPV4_ADDRESS = ObservationFactory(
    create_observable_ipv4_address, create_indicator_pattern_ipv4_address
)
OBSERVATION_FACTORY_IPV6_ADDRESS = ObservationFactory(
    create_observable_ipv6_address, create_indicator_pattern_ipv6_address
)
OBSERVATION_FACTORY_DOMAIN_NAME = ObservationFactory(
    create_observable_domain_name, create_indicator_pattern_domain_name
)
OBSERVATION_FACTORY_HOSTNAME = ObservationFactory(
    create_observable_hostname, create_indicator_pattern_hostname
)
OBSERVATION_FACTORY_EMAIL_ADDRESS = ObservationFactory(
    create_observable_email_address, create_indicator_pattern_email_address
)
OBSERVATION_FACTORY_URL = ObservationFactory(
    create_observable_url, create_indicator_pattern_url
)
OBSERVATION_FACTORY_FILE_MD5 = ObservationFactory(
    create_observable_file_md5, create_indicator_pattern_file_md5
)
OBSERVATION_FACTORY_FILE_SHA1 = ObservationFactory(
    create_observable_file_sha1, create_indicator_pattern_file_sha1
)
OBSERVATION_FACTORY_FILE_SHA256 = ObservationFactory(
    create_observable_file_sha256, create_indicator_pattern_file_sha256
)
OBSERVATION_FACTORY_FILE_NAME = ObservationFactory(
    create_observable_file_name, create_indicator_pattern_file_name
)
OBSERVATION_FACTORY_MUTEX = ObservationFactory(
    create_observable_mutex, create_indicator_pattern_mutex
)
OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET = ObservationFactory(
    create_observable_cryptocurrency_wallet,
    create_indicator_pattern_cryptocurrency_wallet,
)
OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME = ObservationFactory(
    create_observable_windows_service_name,
    create_indicator_pattern_windows_service_name,
)
OBSERVATION_FACTORY_X509_CERTIFICATE_SERIAL_NUMBER = ObservationFactory(
    create_observable_x509_certificate_serial_number,
    create_indicator_pattern_x509_certificate_serial_number,
)
OBSERVATION_FACTORY_X509_CERTIFICATE_SUBJECT = ObservationFactory(
    create_observable_x509_certificate_subject,
    create_indicator_pattern_x509_certificate_subject,
)
OBSERVATION_FACTORY_USER_AGENT = ObservationFactory(
    create_observable_user_agent,
    create_indicator_pattern_user_agent,
)
OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT = ObservationFactory(
    create_observable_email_message_subject,
    create_indicator_pattern_email_message_subject,
)


def paginate(func):
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

        while _next_batch(_limit, _offset, _total):
            response = func(*args, limit=_limit, offset=_offset, **kwargs)

            errors = response["errors"]
            if errors:
                logger.error("Query completed with errors")
                for error in errors:
                    logger.error("Error: %s (code: %s)", error.message, error.code)

            meta = response["meta"]
            if meta["pagination"] is not None:
                pagination = meta["pagination"]

                _meta_limit = pagination["limit"]
                _meta_offset = pagination["offset"]
                _meta_total = pagination["total"]

                logger.info(
                    "Query pagination info limit: %s, offset: %s, total: %s",
                    _meta_limit,
                    _meta_offset,
                    _meta_total,
                )

                _offset = _offset + _limit
                _total = _meta_total

            resources = response["resources"]

            if resources is not None:
                resources_count = len(resources)

                logger.info("Query fetched %s resources", resources_count)

                total_count += resources_count

                yield resources
            else:
                total_count = 0

        logger.info("Fetched %s resources in total", total_count)

    return wrapper_paginate


def _next_batch(limit: int, offset: int, total: Optional[int]) -> bool:
    """Determine if there is next batch to fetch."""
    if total is None:
        return True
    return (total - offset) > 0


def get_tlp_string_marking_definition(tlp: str) -> stix2.MarkingDefinition:
    """Get marking definition for given TLP."""
    marking_definition = TLP_MARKING_DEFINITION_MAPPING.get(tlp.lower())
    if marking_definition is None:
        raise ValueError(f"Invalid TLP value '{tlp}'")
    return marking_definition


def datetime_to_timestamp(datetime_value: datetime) -> int:
    """Convert datetime to Unix timestamp."""
    # Use calendar.timegm because the time.mktime assumes that the input is in your
    # local timezone.
    return calendar.timegm(datetime_value.timetuple())


def timestamp_to_datetime(timestamp: int) -> datetime:
    """Convert Unix timestamp to datetime (UTC)."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def datetime_utc_epoch_start() -> datetime:
    """Get Unix epoch start as UTC datetime."""
    return timestamp_to_datetime(0)


def is_timestamp_in_future(timestamp: int) -> bool:
    """Return True if the timestamp is in the future, otherwise False."""
    timestamp_datetime = timestamp_to_datetime(timestamp)
    now = datetime_utc_now()

    return timestamp_datetime > now


def normalize_start_time_and_stop_time(
    start_time: datetime, stop_time: datetime
) -> Tuple[datetime, datetime]:
    """
    Normalize start and stop times.

    Make sure that the stop time is later than the start time, because the
    STIX 2 Relationship object expects the stop time to be later than the start time
    or the creation of Relationship object fails.
    """
    if start_time == stop_time:
        logger.warning("Start time equals stop time, adding 1 second to stop time")

        stop_time += timedelta(seconds=1)
        return start_time, stop_time

    if start_time > stop_time:
        logger.warning("Start time is greater than stop time, swapping times")

        start_time, stop_time = stop_time, start_time

    return start_time, stop_time


def create_external_reference(
    source_name: str, external_id: str, url: str
) -> stix2.ExternalReference:
    """Create an external reference."""
    return stix2.ExternalReference(
        source_name=source_name, url=url, external_id=external_id
    )


def create_vulnerability_external_references(
    name: str,
) -> List[stix2.ExternalReference]:
    """Create an external references for vulnerability."""
    external_references = []

    if name.startswith("CVE-"):
        external_reference = create_external_reference(
            "NIST NVD", f"https://nvd.nist.gov/vuln/detail/{name}", name
        )
        external_references.append(external_reference)

    return external_references


def create_identity(
    name: str,
    created_by: Optional[stix2.Identity] = None,
    identity_class: Optional[str] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> stix2.Identity:
    """Create an identity."""
    if custom_properties is None:
        custom_properties = {}

    return stix2.Identity(
        id=Identity.generate_id(name, identity_class),
        created_by_ref=created_by,
        name=name,
        identity_class=identity_class,
        custom_properties=custom_properties,
    )


def create_vulnerability(
    name: str,
    created_by: Optional[stix2.Identity] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
) -> stix2.Vulnerability:
    """Create a vulnerability."""
    return stix2.Vulnerability(
        id=Vulnerability.generate_id(name),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
    )


def create_malware(
    name: str,
    malware_id: Optional[str] = None,
    created_by: Optional[stix2.Identity] = None,
    is_family: bool = False,
    aliases: Optional[List[str]] = None,
    kill_chain_phases: Optional[List[stix2.KillChainPhase]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
) -> stix2.Malware:
    """Create a malware."""
    if malware_id is None:
        malware_id = Malware.generate_id(name)

    return stix2.Malware(
        id=malware_id,
        created_by_ref=created_by,
        name=name,
        is_family=is_family,
        aliases=aliases,
        kill_chain_phases=kill_chain_phases,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_kill_chain_phase(
    kill_chain_name: str, phase_name: str
) -> stix2.KillChainPhase:
    """Create a kill chain phase."""
    return stix2.KillChainPhase(kill_chain_name=kill_chain_name, phase_name=phase_name)


def create_intrusion_set(
    name: str,
    created_by: Optional[stix2.Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    description: Optional[str] = None,
    aliases: Optional[List[str]] = None,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
    goals: Optional[List[str]] = None,
    resource_level: Optional[str] = None,
    primary_motivation: Optional[str] = None,
    secondary_motivations: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
) -> stix2.IntrusionSet:
    """Create an intrusion set."""
    return stix2.IntrusionSet(
        id=IntrusionSet.generate_id(name),
        created_by_ref=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        aliases=aliases,
        first_seen=first_seen,
        last_seen=last_seen,
        goals=goals,
        resource_level=resource_level,
        primary_motivation=primary_motivation,
        secondary_motivations=secondary_motivations,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
    )


def create_intrusion_sets_from_names(
    names: List[str],
    created_by: Optional[stix2.Identity] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
) -> List[stix2.IntrusionSet]:
    """Create intrusion sets from given names."""
    intrusion_sets = []

    for name in names:
        intrusion_set = create_intrusion_set_from_name(
            name,
            created_by=created_by,
            confidence=confidence,
            object_markings=object_markings,
        )

        intrusion_sets.append(intrusion_set)

    return intrusion_sets


def create_intrusion_set_from_name(
    name: str,
    created_by: Optional[stix2.Identity] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
) -> stix2.IntrusionSet:
    """Create intrusion set from given name."""
    aliases: List[str] = []

    alias = name.replace(" ", "")
    if alias != name:
        aliases.append(alias)

    return create_intrusion_set(
        name,
        created_by=created_by,
        aliases=aliases,
        confidence=confidence,
        external_references=external_references,
        object_markings=object_markings,
    )


def create_organization(
    name: str, created_by: Optional[stix2.Identity] = None
) -> stix2.Identity:
    """Create an organization."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="organization",
    )


def create_sector(name: str, created_by: stix2.Identity) -> stix2.Identity:
    """Create a sector."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="class",
    )


def create_sector_from_entity(entity, created_by) -> Optional[stix2.Identity]:
    """Create a sector from an entity."""
    name = entity["value"]
    if name is None or not name:
        return None

    return create_sector(name, created_by)


def create_sectors_from_entities(
    entities, created_by: stix2.Identity
) -> List[stix2.Identity]:
    """Create sectors from entities."""
    sectors = []

    for entity in entities:
        sector = create_sector_from_entity(entity, created_by)
        if sector is None:
            continue

        sectors.append(sector)

    return sectors


def create_location(
    name: str,
    created_by: Optional[stix2.Identity] = None,
    region: Optional[str] = None,
    country: Optional[str] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> stix2.Location:
    """Create a location."""
    if custom_properties is None:
        custom_properties = {}

    location_id = Location.generate_id(name, "Region")
    if country is not None:
        location_id = Location.generate_id(name, "Country")

    return stix2.Location(
        id=location_id,
        created_by_ref=created_by,
        name=name,
        region=region,
        country=country,
        custom_properties=custom_properties,
    )


def create_region(name: str, created_by: stix2.Identity) -> stix2.Location:
    """Create a region."""
    return create_location(
        name,
        created_by=created_by,
        region=name,
        custom_properties={X_OPENCTI_LOCATION_TYPE: LocationTypes.REGION.value},
    )


def create_region_from_entity(entity, created_by: stix2.Identity) -> stix2.Location:
    """Create a region from an entity."""
    name = entity["value"]
    if name is None:
        raise TypeError("Entity value is None")

    return create_region(name, created_by=created_by)


def create_country(name: str, code: str, created_by: stix2.Identity) -> stix2.Location:
    """Create a country."""
    code = code.upper()

    return create_location(
        name,
        created_by=created_by,
        country=code,
        custom_properties={
            X_OPENCTI_ALIASES: [code],
            X_OPENCTI_LOCATION_TYPE: LocationTypes.COUNTRY.value,
        },
    )


def create_country_from_entity(entity, created_by: stix2.Identity) -> stix2.Location:
    """Create a country from an entity."""
    name = entity["value"]
    if name is None:
        raise TypeError("Entity value is None")

    code = entity["slug"]
    if code is None:
        raise TypeError("Entity slug is None")

    return create_country(name, code, created_by)


def create_relationship(
    relationship_type: str,
    created_by: stix2.Identity,
    source: _DomainObject,
    target: _DomainObject,
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> stix2.Relationship:
    """Create a relationship."""
    return stix2.Relationship(
        id=StixCoreRelationship.generate_id(
            relationship_type, source.id, target.id, start_time, stop_time
        ),
        created_by_ref=created_by,
        relationship_type=relationship_type,
        source_ref=source,
        target_ref=target,
        start_time=start_time,
        stop_time=stop_time,
        confidence=confidence,
        object_marking_refs=object_markings,
        allow_custom=True,
    )


def create_relationships(
    relationship_type: str,
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create relationships."""
    relationships = []
    for source in sources:
        for target in targets:
            relationship = create_relationship(
                relationship_type,
                created_by,
                source,
                target,
                confidence,
                object_markings,
                start_time=start_time,
                stop_time=stop_time,
            )
            relationships.append(relationship)
    return relationships


def create_targets_relationships(
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create 'targets' relationships."""
    return create_relationships(
        "targets",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_uses_relationships(
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create 'uses' relationships."""
    return create_relationships(
        "uses",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_indicates_relationships(
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create 'indicates' relationships."""
    return create_relationships(
        "indicates",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_originates_from_relationships(
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create 'originates-from' relationships."""
    return create_relationships(
        "originates-from",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_based_on_relationships(
    created_by: stix2.Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[stix2.Relationship]:
    """Create 'based-on' relationships."""
    return create_relationships(
        "based-on",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
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


def create_tag(entity, source_name: str, color: str) -> Mapping[str, str]:
    """Create a tag."""
    value = entity["value"]
    if value is None:
        value = f'NO_VALUE_{entity["id"]}'

    return {"tag_type": source_name, "value": value, "color": color}


def create_tags(entities, source_name: str) -> List[Mapping[str, str]]:
    """Create tags."""
    color = "#cf3217"

    tags = []
    for entity in entities:
        tag = create_tag(entity, source_name, color)
        tags.append(tag)
    return tags


def remove_html_tags(html_text: str) -> str:
    """Remove HTML tags from given string."""
    document = fromstring(html_text)
    text = document.text_content()
    return text.strip()


def create_report(
    name: str,
    published: datetime,
    objects: List[Union[_DomainObject, _RelationshipObject]],
    created_by: Optional[stix2.Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    description: Optional[str] = None,
    report_types: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
    x_opencti_report_status: Optional[int] = None,
    x_opencti_files: Optional[List[Mapping[str, Union[str, bool]]]] = None,
) -> stix2.Report:
    """Create a report."""
    return stix2.Report(
        id=PyCTIReport.generate_id(name, published),
        created_by_ref=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        report_types=report_types,
        published=published,
        object_refs=objects,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
        custom_properties={
            X_OPENCTI_REPORT_STATUS: x_opencti_report_status,
            X_OPENCTI_FILES: x_opencti_files,
        },
        allow_custom=True,
    )


def create_stix2_report_from_report(
    report,
    source_name: str,
    created_by: stix2.Identity,
    objects: List[Union[_DomainObject, _RelationshipObject]],
    report_types: List[str],
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    x_opencti_report_status: int,
    x_opencti_files: Optional[List[Mapping[str, Union[str, bool]]]] = None,
) -> stix2.Report:
    """Create a STIX2 report from Report."""
    report_name = report["name"]

    report_created_date = timestamp_to_datetime(report["created_date"])
    if report_created_date is None:
        report_created_date = datetime_utc_now()

    report_last_modified_date = timestamp_to_datetime(report["last_modified_date"])
    if report_last_modified_date is None:
        report_last_modified_date = report_created_date

    report_description = report["description"]
    report_rich_text_description = report["rich_text_description"]
    report_short_description = report["short_description"]

    description = None
    if report_rich_text_description is not None and report_rich_text_description:
        description = remove_html_tags(report_rich_text_description)
    elif report_description is not None and report_description:
        description = report_description
    elif report_short_description:
        description = report_short_description

    labels = []
    report_tags = report["tags"]
    if report_tags is not None:
        for tag in report_tags:
            value = tag["value"]
            if value is None or not value:
                continue

            labels.append(value)

    external_references = []
    report_url = report["url"]
    if report_url is not None and report_url:
        external_reference = create_external_reference(
            source_name, str(report["id"]), report_url
        )
        external_references.append(external_reference)

    return create_report(
        report_name,
        report_created_date,
        objects,
        created_by=created_by,
        created=report_created_date,
        modified=report_last_modified_date,
        description=description,
        report_types=report_types,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_markings=object_markings,
        x_opencti_report_status=x_opencti_report_status,
        x_opencti_files=x_opencti_files,
    )


def create_regions_and_countries_from_entities(
    entities: list, author: stix2.Identity
) -> Tuple[List[stix2.Location], List[stix2.Location]]:
    """Create regions and countries from given entities."""
    regions = []
    countries = []

    for entity in entities:
        if entity["slug"] is None or entity["value"] is None:
            continue

        # Do not create region/country for unknown.
        if entity["slug"] == "unknown":
            continue

        # Target countries may also contain regions.
        # Use hack to differentiate between countries and regions.
        if len(entity["slug"]) > 2:
            target_region = create_region_from_entity(entity, author)

            regions.append(target_region)
        else:
            target_country = create_country_from_entity(entity, author)

            countries.append(target_country)

    return regions, countries


def create_file_from_download(
    download, report_name: str
) -> Mapping[str, Union[str, bool]]:

    converted_report_pdf = BytesIO(download)

    filename = report_name.lower().replace(" ", "-") + ".pdf"
    if filename is None or not filename:
        logger.error("File download missing a filename")
        filename = "DOWNLOAD_MISSING_FILENAME"

    base64_data = base64.b64encode(converted_report_pdf.read())

    return {
        "name": filename,
        "data": base64_data.decode("utf-8"),
        "mime_type": "application/pdf",
        "no_trigger_import": True,
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


def create_indicator(
    pattern: str,
    pattern_type: str,
    created_by: Optional[stix2.Identity] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    kill_chain_phases: Optional[List[stix2.KillChainPhase]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
    x_opencti_main_observable_type: Optional[str] = None,
    x_opencti_score: Optional[int] = None,
) -> stix2.Indicator:
    """Create an indicator."""
    custom_properties: Dict[str, Any] = {X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}

    if x_opencti_score is not None:
        custom_properties[X_OPENCTI_SCORE] = x_opencti_score

    if x_opencti_main_observable_type is not None:
        custom_properties[X_OPENCTI_MAIN_OBSERVABLE_TYPE] = (
            x_opencti_main_observable_type
        )

    return stix2.Indicator(
        id=Indicator.generate_id(pattern),
        created_by_ref=created_by,
        name=name,
        description=description,
        pattern=pattern,
        pattern_type=pattern_type,
        valid_from=valid_from,
        kill_chain_phases=kill_chain_phases,
        labels=labels,
        confidence=confidence,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )
