# -*- coding: utf-8 -*-
"""OpenCTI AlienVault utilities module."""

from datetime import datetime
from typing import List, Mapping, Optional, Union

from pycti.utils.constants import CustomProperties

from stix2 import (
    AttackPattern,
    EqualityComparisonExpression,
    ExternalReference,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    MarkingDefinition,
    ObjectPath,
    ObservationExpression,
    Relationship,
    StringConstant,
    Vulnerability,
)
from stix2.core import STIXDomainObject, STIXRelationshipObject


def create_equality_observation_expression_str(
    object_path: ObjectPath, value: str
) -> str:
    """Create observation expression string with pattern equality comparison expression."""  # noqa: E501
    operand = EqualityComparisonExpression(object_path, StringConstant(value))
    observation_expression = ObservationExpression(str(operand))
    return str(observation_expression)


def create_object_path(object_type: str, property_path: List[str]) -> ObjectPath:
    """Create pattern operand object (property) path."""
    return ObjectPath(object_type, property_path)


def iso_datetime_str_to_datetime(string):
    """Concert ISO datetime string to datetime object."""
    try:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S")


def create_external_reference(
    source_name: str, url: str, external_id: Optional[str] = None
) -> ExternalReference:
    """Create an external reference."""
    return ExternalReference(source_name=source_name, url=url, external_id=external_id)


def create_indicator(
    name: str,
    author: Identity,
    description: str,
    valid_from: datetime,
    observable_type: str,
    observable_value: str,
    pattern_type: str,
    pattern_value: str,
    indicator_pattern: str,
    object_marking_refs: List[MarkingDefinition],
) -> Indicator:
    """Create an indicator."""
    return Indicator(
        created_by_ref=author,
        name=name,
        description=description,
        pattern=str(pattern_value),
        valid_from=valid_from,
        labels=["malicious-activity"],
        object_marking_refs=object_marking_refs,
        custom_properties={
            CustomProperties.OBSERVABLE_TYPE: observable_type,
            CustomProperties.OBSERVABLE_VALUE: observable_value,
            CustomProperties.PATTERN_TYPE: pattern_type,
            CustomProperties.INDICATOR_PATTERN: indicator_pattern,
        },
    )


def create_intrusion_set(
    name: str, author: Identity, object_marking_refs: List[MarkingDefinition],
) -> IntrusionSet:
    """Create an intrusion set."""
    return IntrusionSet(
        created_by_ref=author,
        name=name,
        labels=["intrusion-set"],
        object_marking_refs=object_marking_refs,
    )


def create_malware(
    name: str, author: Identity, object_marking_refs: List[MarkingDefinition],
) -> Malware:
    """Create a malware."""
    return Malware(
        created_by_ref=author,
        name=name,
        labels=["malware"],
        object_marking_refs=object_marking_refs,
    )


def create_sector(name: str, author: Identity) -> Identity:
    """Create a sector."""
    return Identity(
        created_by_ref=author,
        name=name,
        identity_class="class",
        custom_properties={CustomProperties.IDENTITY_TYPE: "sector"},
    )


def create_country(name: str, author: Identity) -> Identity:
    """Create a country."""
    return Identity(
        created_by_ref=author,
        name=name,
        identity_class="group",
        custom_properties={CustomProperties.IDENTITY_TYPE: "country"},
    )


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


def create_vulnerability_external_reference(name: str) -> List[ExternalReference]:
    """Create an external reference for vulnerability."""
    external_references = []
    if name.startswith("CVE-"):
        external_reference = create_external_reference(
            "NIST NVD", f"https://nvd.nist.gov/vuln/detail/{name}", name,
        )
        external_references.append(external_reference)
    return external_references


def create_attack_pattern(
    name: str,
    author: Identity,
    external_references: List[ExternalReference],
    object_marking_refs: List[MarkingDefinition],
) -> AttackPattern:
    """Create an attack pattern."""
    return AttackPattern(
        created_by_ref=author,
        name=name,
        labels=["attack-pattern"],
        external_references=external_references,
        object_marking_refs=object_marking_refs,
        custom_properties={CustomProperties.EXTERNAL_ID: name},
    )


def create_attack_pattern_external_reference(name: str) -> List[ExternalReference]:
    """Create an external reference for attack pattern."""
    external_references = []
    if name.startswith("T"):
        external_reference = create_external_reference(
            "mitre-attack", f"https://attack.mitre.org/techniques/{name}", name,
        )
        external_references.append(external_reference)
    return external_references


def create_relationship(
    relationship_type: str,
    author: Identity,
    source: STIXDomainObject,
    target: STIXDomainObject,
    object_marking_refs: List[MarkingDefinition],
    first_seen: datetime,
    last_seen: datetime,
    confidence_level: int,
) -> Relationship:
    """Create a relationship."""
    return Relationship(
        created_by_ref=author,
        relationship_type=relationship_type,
        source_ref=source.id,
        target_ref=target.id,
        object_marking_refs=object_marking_refs,
        custom_properties={
            CustomProperties.FIRST_SEEN: first_seen,
            CustomProperties.LAST_SEEN: last_seen,
            CustomProperties.WEIGHT: confidence_level,
        },
    )


def create_relationships(
    relationship_type: str,
    author: Identity,
    sources: List[STIXDomainObject],
    targets: List[STIXDomainObject],
    object_marking_refs: List[MarkingDefinition],
    first_seen: datetime,
    last_seen: datetime,
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
                first_seen,
                last_seen,
                confidence_level,
            )
            relationships.append(relationship)
    return relationships


def create_uses_relationships(
    author: Identity,
    sources: List[STIXDomainObject],
    targets: List[STIXDomainObject],
    object_marking_refs: List[MarkingDefinition],
    first_seen: datetime,
    last_seen: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'uses' relationships."""
    return create_relationships(
        "uses",
        author,
        sources,
        targets,
        object_marking_refs,
        first_seen,
        last_seen,
        confidence_level,
    )


def create_targets_relationships(
    author: Identity,
    sources: List[STIXDomainObject],
    targets: List[STIXDomainObject],
    object_marking_refs: List[MarkingDefinition],
    first_seen: datetime,
    last_seen: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'targets' relationships."""
    return create_relationships(
        "targets",
        author,
        sources,
        targets,
        object_marking_refs,
        first_seen,
        last_seen,
        confidence_level,
    )


def create_indicates_relationships(
    author: Identity,
    sources: List[STIXDomainObject],
    targets: List[STIXDomainObject],
    object_marking_refs: List[MarkingDefinition],
    first_seen: datetime,
    last_seen: datetime,
    confidence_level: int,
) -> List[Relationship]:
    """Create 'indicates' relationships."""
    return create_relationships(
        "indicates",
        author,
        sources,
        targets,
        object_marking_refs,
        first_seen,
        last_seen,
        confidence_level,
    )


def create_object_refs(
    *objects: Union[
        STIXDomainObject,
        STIXRelationshipObject,
        List[STIXRelationshipObject],
        List[STIXDomainObject],
    ]
) -> List[STIXDomainObject]:
    """Create object references."""
    object_refs = []
    for obj in objects:
        if isinstance(obj, STIXDomainObject):
            object_refs.append(obj)
        else:
            object_refs.extend(obj)
    return object_refs


def create_tag(tag_type: str, tag_value: str, tag_color: str) -> Mapping[str, str]:
    """Create a tag."""
    return {"tag_type": tag_type, "value": tag_value, "color": tag_color}
