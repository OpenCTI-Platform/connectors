"""OpenCTI Cybersixgill utilities module."""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional

import stix2
from pycti import Identity, Indicator, StixCoreRelationship
from stix2.v21 import _DomainObject, _Observable  # type: ignore

from cybersixgill.utils.constants import (
    DEFAULT_X_OPENCTI_SCORE,
    X_OPENCTI_MAIN_OBSERVABLE_TYPE,
    X_OPENCTI_SCORE,
)
from cybersixgill.utils.indicators import (
    IndicatorPattern,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_file_md5,
    create_indicator_pattern_file_name,
    create_indicator_pattern_file_sha1,
    create_indicator_pattern_file_sha256,
    create_indicator_pattern_hostname,
    create_indicator_pattern_ipv4_address,
    create_indicator_pattern_ipv6_address,
    create_indicator_pattern_url,
)
from cybersixgill.utils.observables import (
    ObservableProperties,
    create_observable_domain_name,
    create_observable_file_md5,
    create_observable_file_name,
    create_observable_file_sha1,
    create_observable_file_sha256,
    create_observable_hostname,
    create_observable_ipv4_address,
    create_observable_ipv6_address,
    create_observable_url,
)


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


def iso_datetime_str_to_datetime(string):
    """Concert ISO datetime string to datetime object."""
    try:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S")


def create_organization(
    name: str, created_by: Optional[stix2.Identity] = None
) -> stix2.Identity:
    """Create an organization."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="organization",
    )


def create_identity(
    name: str,
    identity_id: Optional[str] = None,
    created_by: Optional[stix2.Identity] = None,
    identity_class: Optional[str] = None,
    custom_properties: Optional[Mapping[str, str]] = None,
) -> stix2.Identity:
    """Create an identity."""
    if identity_id is None:
        identity_id = Identity.generate_id(name, identity_class)

    if custom_properties is None:
        custom_properties = {}

    return stix2.Identity(
        id=identity_id,
        created_by_ref=created_by,
        name=name,
        identity_class=identity_class,
        custom_properties=custom_properties,
    )


def create_external_reference(
    source_name: str, url: str, description: str, external_id: Optional[str] = None
) -> stix2.ExternalReference:
    """Create an external reference."""
    return stix2.ExternalReference(
        source_name=source_name, url=url, external_id=external_id
    )


def create_indicator(
    pattern: str,
    pattern_type: str,
    created,
    modified,
    created_by: Optional[stix2.Identity] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
    x_opencti_main_observable_type: Optional[str] = None,
    revoked: Optional[bool] = False,
) -> stix2.Indicator:
    """Create an indicator."""
    custom_properties: Dict[str, Any] = {X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}

    if x_opencti_main_observable_type is not None:
        custom_properties[
            X_OPENCTI_MAIN_OBSERVABLE_TYPE
        ] = x_opencti_main_observable_type

    data = stix2.Indicator(
        id=Indicator.generate_id(pattern),
        created_by_ref=created_by,
        name=name,
        description=description,
        created=created,
        modified=modified,
        pattern=pattern,
        pattern_type=pattern_type,
        valid_from=valid_from,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
        revoked=revoked,
    )
    return data


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


def timestamp_to_datetime(timestamp: int) -> datetime:
    """Convert Unix timestamp to datetime (UTC)."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
