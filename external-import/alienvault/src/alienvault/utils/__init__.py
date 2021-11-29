# -*- coding: utf-8 -*-
"""OpenCTI AlienVault utilities module."""

from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Union

from pycti import OpenCTIStix2Utils  # type: ignore
from pycti.utils.constants import LocationTypes  # type: ignore

from stix2 import (  # type: ignore
    AttackPattern,
    ExternalReference,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Relationship,
    Report,
    Vulnerability,
)
from stix2.v21 import _DomainObject, _Observable, _RelationshipObject  # type: ignore

from alienvault.utils.constants import (
    DEFAULT_X_OPENCTI_SCORE,
    TLP_MARKING_DEFINITION_MAPPING,
    X_MITRE_ID,
    X_OPENCTI_LOCATION_TYPE,
    X_OPENCTI_MAIN_OBSERVABLE_TYPE,
    X_OPENCTI_REPORT_STATUS,
    X_OPENCTI_SCORE,
)
from alienvault.utils.indicators import (
    IndicatorPattern,
    create_indicator_pattern_cryptocurrency_wallet,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_email_address,
    create_indicator_pattern_file_md5,
    create_indicator_pattern_file_name,
    create_indicator_pattern_file_sha1,
    create_indicator_pattern_file_sha256,
    create_indicator_pattern_hostname,
    create_indicator_pattern_ipv4_address,
    create_indicator_pattern_ipv6_address,
    create_indicator_pattern_mutex,
    create_indicator_pattern_url,
)
from alienvault.utils.observables import (
    ObservableProperties,
    create_observable_cryptocurrency_wallet,
    create_observable_domain_name,
    create_observable_email_address,
    create_observable_file_md5,
    create_observable_file_name,
    create_observable_file_sha1,
    create_observable_file_sha256,
    create_observable_hostname,
    create_observable_ipv4_address,
    create_observable_ipv6_address,
    create_observable_mutex,
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


def get_tlp_string_marking_definition(tlp: str) -> MarkingDefinition:
    """Get marking definition for given TLP."""
    marking_definition = TLP_MARKING_DEFINITION_MAPPING.get(tlp.lower())
    if marking_definition is None:
        raise ValueError(f"Invalid TLP value '{tlp}'")
    return marking_definition


def iso_datetime_str_to_datetime(string):
    """Concert ISO datetime string to datetime object."""
    try:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S")


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


def _create_random_identifier(identifier_type: str) -> str:
    return OpenCTIStix2Utils.generate_random_stix_id(identifier_type)


def create_organization(name: str, created_by: Optional[Identity] = None) -> Identity:
    """Create an organization."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="organization",
    )


def create_identity(
    name: str,
    identity_id: Optional[str] = None,
    created_by: Optional[Identity] = None,
    identity_class: Optional[str] = None,
    custom_properties: Optional[Mapping[str, str]] = None,
) -> Identity:
    """Create an identity."""
    if identity_id is None:
        identity_id = _create_random_identifier("identity")

    if custom_properties is None:
        custom_properties = {}

    return Identity(
        id=identity_id,
        created_by_ref=created_by,
        name=name,
        identity_class=identity_class,
        custom_properties=custom_properties,
    )


def create_external_reference(
    source_name: str, url: str, external_id: Optional[str] = None
) -> ExternalReference:
    """Create an external reference."""
    return ExternalReference(source_name=source_name, url=url, external_id=external_id)


def create_indicator(
    pattern: str,
    pattern_type: str,
    created_by: Optional[Identity] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    x_opencti_main_observable_type: Optional[str] = None,
) -> Indicator:
    """Create an indicator."""
    custom_properties: Dict[str, Any] = {X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}

    if x_opencti_main_observable_type is not None:
        custom_properties[
            X_OPENCTI_MAIN_OBSERVABLE_TYPE
        ] = x_opencti_main_observable_type

    return Indicator(
        id=_create_random_identifier("indicator"),
        created_by_ref=created_by,
        name=name,
        description=description,
        pattern=pattern,
        pattern_type=pattern_type,
        valid_from=valid_from,
        labels=labels,
        confidence=confidence,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )


def create_intrusion_set(
    name: str,
    created_by: Identity,
    confidence: int,
    object_markings: List[MarkingDefinition],
) -> IntrusionSet:
    """Create an intrusion set."""
    return IntrusionSet(
        id=_create_random_identifier("intrusion-set"),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_malware(
    name: str,
    created_by: Identity,
    confidence: int,
    object_markings: List[MarkingDefinition],
    malware_id: Optional[str] = None,
    is_family: bool = False,
) -> Malware:
    """Create a malware."""
    if malware_id is None:
        malware_id = _create_random_identifier("malware")

    return Malware(
        id=malware_id,
        created_by_ref=created_by,
        name=name,
        is_family=is_family,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_sector(name: str, created_by: Identity) -> Identity:
    """Create a sector."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="class",
    )


def create_country(name: str, created_by: Identity) -> Location:
    """Create a country."""
    return Location(
        id=_create_random_identifier("location"),
        created_by_ref=created_by,
        name=name,
        country="ZZ",  # TODO: Country code is required by STIX2!
        custom_properties={X_OPENCTI_LOCATION_TYPE: LocationTypes.COUNTRY.value},
    )


def create_vulnerability(
    name: str,
    created_by: Identity,
    confidence: int,
    external_references: List[ExternalReference],
    object_markings: List[MarkingDefinition],
) -> Vulnerability:
    """Create a vulnerability."""
    return Vulnerability(
        id=_create_random_identifier("vulnerability"),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
    )


def create_vulnerability_external_reference(name: str) -> List[ExternalReference]:
    """Create an external reference for vulnerability."""
    external_references = []
    if name.startswith("CVE-"):
        external_reference = create_external_reference(
            "NIST NVD", f"https://nvd.nist.gov/vuln/detail/{name}", name
        )
        external_references.append(external_reference)
    return external_references


def create_attack_pattern(
    name: str,
    created_by: Identity,
    confidence: int,
    external_references: List[ExternalReference],
    object_markings: List[MarkingDefinition],
) -> AttackPattern:
    """Create an attack pattern."""
    return AttackPattern(
        id=_create_random_identifier("attack-pattern"),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
        custom_properties={X_MITRE_ID: name},
    )


def create_attack_pattern_external_reference(name: str) -> List[ExternalReference]:
    """Create an external reference for attack pattern."""
    external_references = []
    if name.startswith("T"):
        path = name.replace(".", "/")
        external_reference = create_external_reference(
            "mitre-attack", f"https://attack.mitre.org/techniques/{path}", name
        )
        external_references.append(external_reference)
    return external_references


def create_relationship(
    relationship_type: str,
    created_by: Identity,
    source: _DomainObject,
    target: _DomainObject,
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> Relationship:
    """Create a relationship."""
    return Relationship(
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
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
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


def create_uses_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
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


def create_targets_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
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


def create_indicates_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
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


def create_based_on_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
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


def create_report(
    name: str,
    published: datetime,
    objects: List[Union[_DomainObject, _RelationshipObject]],
    created_by: Optional[Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    description: Optional[str] = None,
    report_types: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[ExternalReference]] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    x_opencti_report_status: Optional[int] = None,
) -> Report:
    """Create a report."""
    return Report(
        id=_create_random_identifier("report"),
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
        custom_properties={X_OPENCTI_REPORT_STATUS: x_opencti_report_status},
        allow_custom=True,
    )
