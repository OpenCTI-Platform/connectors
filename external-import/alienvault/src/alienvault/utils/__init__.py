# -*- coding: utf-8 -*-
"""OpenCTI AlienVault utilities module."""

from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Union

import stix2
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
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    Report,
    StixCoreRelationship,
    Vulnerability,
)
from pycti.utils.constants import LocationTypes  # type: ignore
from stix2.v21 import _DomainObject, _Observable, _RelationshipObject  # type: ignore


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


def get_tlp_string_marking_definition(tlp: str) -> stix2.MarkingDefinition:
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
    source_name: str, url: str, external_id: Optional[str] = None
) -> stix2.ExternalReference:
    """Create an external reference."""
    return stix2.ExternalReference(
        source_name=source_name, url=url, external_id=external_id
    )


def create_indicator(
    pattern: str,
    pattern_type: str,
    created_by: Optional[stix2.Identity] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[stix2.MarkingDefinition]] = None,
    x_opencti_main_observable_type: Optional[str] = None,
    external_references: Optional[List[stix2.ExternalReference]] = None,
    created: Optional[datetime] = None,
) -> stix2.Indicator:
    """Create an indicator."""
    custom_properties: Dict[str, Any] = {X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}

    if x_opencti_main_observable_type is not None:
        custom_properties[
            X_OPENCTI_MAIN_OBSERVABLE_TYPE
        ] = x_opencti_main_observable_type

    return stix2.Indicator(
        id=Indicator.generate_id(pattern),
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
        external_references=external_references,
        created=created
    )


def create_intrusion_set(
    name: str,
    created_by: stix2.Identity,
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
) -> stix2.IntrusionSet:
    """Create an intrusion set."""
    return stix2.IntrusionSet(
        id=IntrusionSet.generate_id(name),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_malware(
    name: str,
    created_by: stix2.Identity,
    confidence: int,
    object_markings: List[stix2.MarkingDefinition],
    malware_id: Optional[str] = None,
    is_family: bool = False,
) -> stix2.Malware:
    """Create a malware."""
    if malware_id is None:
        malware_id = Malware.generate_id(name)

    return stix2.Malware(
        id=malware_id,
        created_by_ref=created_by,
        name=name,
        is_family=is_family,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_sector(name: str, created_by: stix2.Identity) -> stix2.Identity:
    """Create a sector."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="class",
    )


def create_country(name: str, created_by: stix2.Identity) -> stix2.Location:
    """Create a country."""
    return stix2.Location(
        id=Location.generate_id(name, "Country"),
        created_by_ref=created_by,
        name=name,
        country="ZZ",  # TODO: Country code is required by STIX2!
        custom_properties={X_OPENCTI_LOCATION_TYPE: LocationTypes.COUNTRY.value},
    )


def create_vulnerability(
    name: str,
    created_by: stix2.Identity,
    confidence: int,
    external_references: List[stix2.ExternalReference],
    object_markings: List[stix2.MarkingDefinition],
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


def create_vulnerability_external_reference(name: str) -> List[stix2.ExternalReference]:
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
    created_by: stix2.Identity,
    confidence: int,
    external_references: List[stix2.ExternalReference],
    object_markings: List[stix2.MarkingDefinition],
) -> stix2.AttackPattern:
    """Create an attack pattern."""
    return stix2.AttackPattern(
        id=AttackPattern.generate_id(name, name),
        created_by_ref=created_by,
        name=name,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
        custom_properties={X_MITRE_ID: name},
    )


def create_attack_pattern_external_reference(
    name: str,
) -> List[stix2.ExternalReference]:
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
) -> stix2.Report:
    """Create a report."""
    return stix2.Report(
        id=Report.generate_id(name, published),
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
