from abc import abstractmethod
from datetime import datetime
from typing import Any

import stix2
from pycti import AttackPattern as PyCTIAttackPattern
from pycti import CaseIncident as PyCTICaseIncident
from pycti import CustomObjectCaseIncident as PyCTICustomCaseIncident
from pycti import CustomObservableHostname as PyCTICustomObservableHostname
from pycti import Identity as PyCTIIdentity
from pycti import Incident as PyCTIIncident
from pycti import Indicator as PyCTIIndicator
from pycti import Note as PyCTINote
from pycti import StixCoreRelationship as PyCTIRelationship
from pycti import StixSightingRelationship as PyCTISighting

from ..constants import MARKING_DEFINITIONS_BY_NAME
from ..utils import is_domain, is_ipv4, is_ipv6

DEFAULT_MARKING_DEFINITIONS = (
    MARKING_DEFINITIONS_BY_NAME["TLP:CLEAR"],
)  # trailing space is required for one-element tuples


class BaseModel:
    """
    Base class for OpenCTI models.
    """

    _stix2_representation: dict = None
    _id: str = None

    def __post_init__(self):
        self._stix2_representation = self.to_stix2_object()
        self._id = self._stix2_representation["id"]

    @property
    def id(self):
        return self._id

    @property
    def stix2_representation(self):
        if self._stix2_representation is None:
            self._stix2_representation = self.to_stix2_object()
        return self._stix2_representation

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct STIX 2.1 object (usually from stix2 python lib objects)"""
        ...


class AttackPattern(BaseModel):
    """
    Represent an AttackPattern indicator in OpenCTI.
    """

    def __init__(
        self,
        name: str | None = None,
        x_mitre_id: str | None = None,
        author=None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.name = name
        self.x_mitre_id = x_mitre_id
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.AttackPattern:
        return stix2.AttackPattern(
            id=PyCTIAttackPattern.generate_id(self.name, self.x_mitre_id),
            name=self.name,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "x_mitre_id": self.x_mitre_id,
                "created_by_ref": self.author.id,
            },
        )


class Author(BaseModel):
    """
    Represent an Author organization in OpenCTI.
    """

    def __init__(
        self,
        name: str | None = None,
        description: str | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        identity_class = "organization"

        self.name = name
        self.description = description
        self.identity_class = identity_class
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=PyCTIIdentity.generate_id(self.name, self.identity_class),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
            object_marking_refs=self.object_marking_refs,
        )


class CaseIncident(BaseModel):
    def __init__(
        self,
        name: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        object_refs: list[dict] | None = None,
        author: Author | None = None,
        created_at: datetime | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
        external_references: list[dict] | None = None,
    ):
        self.name = name
        self.description = description
        self.severity = severity
        self.priority = priority
        self.object_refs = object_refs
        self.author = author
        self.created_at = created_at
        self.object_marking_refs = object_marking_refs
        self.external_references = external_references
        self.__post_init__()

    def to_stix2_object(self) -> PyCTICustomCaseIncident:
        return PyCTICustomCaseIncident(
            id=PyCTICaseIncident.generate_id(self.name, self.created_at),
            name=self.name,
            description=self.description,
            severity=self.severity,
            priority=self.priority,
            object_refs=self.object_refs,
            created=self.created_at,
            created_by_ref=self.author.id,
            object_marking_refs=self.object_marking_refs,
            external_references=self.external_references,
        )


class Directory(BaseModel):
    """
    Represent a Directory observable in OpenCTI.
    """

    def __init__(
        self,
        path: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.path = path
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Directory:
        return stix2.Directory(
            path=self.path,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class DomainName(BaseModel):
    """
    Represent a DomainName observable in OpenCTI.
    """

    def __init__(
        self,
        value: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        if not is_domain(value):
            raise ValueError("Invalid DomainName value")

        self.value = value
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.DomainName:
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class File(BaseModel):
    """
    Represent a File observable in OpenCTI.
    """

    def __init__(
        self,
        name: str | None = None,
        hashes: dict | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.name = name
        self.hashes = hashes
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.File:
        return stix2.File(
            name=self.name,
            hashes=self.hashes,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class Hostname(BaseModel):
    """
    Represent a Hostname observable in OpenCTI.
    """

    def __init__(
        self,
        value: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.value = value
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> PyCTICustomObservableHostname:
        # PyCTICustomObservableHostname is an extension of the STIX2.1 as the spec doesn't implement Hostname observables
        return PyCTICustomObservableHostname(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class IPv4(BaseModel):
    """
    Represent a IPv4 observable in OpenCTI.
    """

    def __init__(
        self,
        value: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        if not is_ipv4(value):
            raise ValueError("Invalid IPv4 address value")

        self.value = value
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.IPv4Address:
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class IPv6(BaseModel):
    """
    Represent a IPv6 observable in OpenCTI.
    """

    def __init__(
        self,
        value: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        if not is_ipv6(value):
            raise ValueError("Invalid IPv6 address value")

        self.value = value
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.IPv6Address:
        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class Incident(BaseModel):
    """
    Represent an Incident event in OpenCTI.
    """

    def __init__(
        self,
        name: str | None = None,
        description: str | None = None,
        source: str | None = None,
        severity: str | None = None,
        author: Author | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
        external_references: list[dict] | None = None,
    ):
        self.name = name
        self.description = description
        self.source = source
        self.severity = severity
        self.author = author
        self.created_at = created_at
        self.updated_at = updated_at
        self.object_marking_refs = object_marking_refs
        self.external_references = external_references
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Incident:
        return stix2.Incident(
            id=PyCTIIncident.generate_id(self.name, self.created_at),
            name=self.name,
            description=self.description,
            created=self.created_at,
            created_by_ref=self.author.id,
            object_marking_refs=self.object_marking_refs,
            external_references=self.external_references,
            custom_properties={
                "source": self.source,
                "severity": self.severity,
                "incident_type": "alert",
                "first_seen": self.created_at,
                "last_seen": self.updated_at,
            },
        )


class Indicator(BaseModel):
    """
    Represent an Indicator in OpenCTI.
    """

    def __init__(
        self,
        name: str | None = None,
        pattern: str | None = None,
        pattern_type: str | None = None,
        x_opencti_score: int | None = None,
        author: Author | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.name = name
        self.pattern = pattern
        self.pattern_type = pattern_type
        self.x_opencti_score = x_opencti_score
        self.author = author
        self.created_at = created_at
        self.updated_at = updated_at
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Indicator:
        return stix2.Indicator(
            id=PyCTIIndicator.generate_id(self.pattern),
            created_by_ref=self.author.id,
            created=self.created_at,
            modified=self.updated_at,
            name=self.name,
            pattern=self.pattern,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "pattern_type": self.pattern_type,
                "x_opencti_score": self.x_opencti_score,
                "detection": True,
            },
        )


class Note(BaseModel):
    def __init__(
        self,
        abstract=None,
        content=None,
        object_refs=None,
        author: Author | None = None,
        created_at=None,
        updated_at=None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
        external_references=None,
    ):

        self.abstract = abstract
        self.content = content
        self.objects_refs = object_refs
        self.author = author
        self.created_at = created_at
        self.updated_at = updated_at
        self.object_marking_refs = object_marking_refs
        self.external_references = external_references
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Note:
        return stix2.Note(
            id=PyCTINote.generate_id(
                self.content,
                self.created_at.isoformat(),  # PyCTINote.generate_id doesn't handle datetime
            ),
            abstract=f"Linked to {self.abstract}",
            content=self.content,
            object_refs=self.objects_refs,
            created=self.created_at,
            modified=self.updated_at,
            created_by_ref=self.author.id,
            object_marking_refs=self.object_marking_refs,
            external_references=self.external_references,
        )


class Relationship(BaseModel):
    def __init__(
        self,
        type=None,
        source=None,
        target=None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.type = type
        self.source = source
        self.target = target
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Relationship:
        return stix2.Relationship(
            id=PyCTIRelationship.generate_id(self.type, self.source.id, self.target.id),
            relationship_type=self.type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            created_by_ref=self.author.id,
            object_marking_refs=self.object_marking_refs,
        )


class Sighting(BaseModel):
    """
    Represent a Sighting event in OpenCTI.
    """

    def __init__(
        self,
        source: Author | None = None,
        target: Indicator | None = None,
        first_seen_at: datetime | None = None,
        last_seen_at: datetime | None = None,
        count: int = 1,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
        x_opencti_negative: bool = False,
        external_references=None,
    ):
        self.source = source
        self.target = target
        self.first_seen_at = first_seen_at
        self.last_seen_at = last_seen_at
        self.count = count
        self.object_marking_refs = object_marking_refs
        self.external_references = external_references
        self.x_opencti_negative = x_opencti_negative
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Sighting:
        return stix2.Sighting(
            id=PyCTISighting.generate_id(
                self.source.id,
                self.target.id,
                self.first_seen_at,
                self.first_seen_at,  # using same date twice avoids duplication
            ),
            first_seen=self.first_seen_at,
            last_seen=self.last_seen_at,
            sighting_of_ref=self.target.id,
            where_sighted_refs=self.source.id,
            count=self.count,
            object_marking_refs=self.object_marking_refs,
            external_references=self.external_references,
            custom_properties={
                "x_opencti_negative": self.x_opencti_negative,
            },
        )


class Url(BaseModel):
    """
    Represent a URL observable in OpenCTI.
    """

    def __init__(
        self,
        value: str | None = None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.value = value
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.URL:
        return stix2.URL(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class UserAccount(BaseModel):
    """
    Represent a UserAccount observable in OpenCTI.
    """

    def __init__(
        self,
        account_login=None,
        author: Author | None = None,
        object_marking_refs: list[
            stix2.MarkingDefinition
        ] = DEFAULT_MARKING_DEFINITIONS,
    ):
        self.account_login = account_login
        self.author = author
        self.object_marking_refs = object_marking_refs
        self.__post_init__()

    def to_stix2_object(self) -> stix2.UserAccount:
        return stix2.UserAccount(
            account_login=self.account_login,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )
