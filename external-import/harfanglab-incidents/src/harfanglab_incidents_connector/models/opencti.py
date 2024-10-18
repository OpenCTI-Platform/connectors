import datetime
from abc import abstractmethod
from typing import Any

from ..utils import is_ipv4, is_ipv6, is_domain  # TODO: replace relative import

import stix2
from pycti import (
    AttackPattern as PyCTIAttackPattern,
    CustomObservableHostname as PyCTIObservableHostname,
    Identity as PyCTIIdentity,
    Incident as PyCTIIncident,
    Indicator as PyCTIIndicator,
    StixSightingRelationship as PyCTISighting,
)


class BaseModel:
    """
    Base class for OpenCTI models.
    """

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct STIX 2.1 object (usually from stix2 python lib objects)"""
        ...


class AttackPattern(BaseModel):
    """
    Represent an AttackPattern indicator in OpenCTI.
    """

    def __init__(
        self, name=None, x_mitre_id=None, author=None, object_marking_refs=None
    ):
        self.name = name
        self.x_mitre_id = x_mitre_id
        self.author = author

    def to_stix2_object(self) -> stix2.AttackPattern:
        return stix2.AttackPattern(
            id=PyCTIAttackPattern.generate_id(self.name, self.name),
            name=self.name,
            custom_properties={
                "x_mitre_id": self.x_mitre_id,
                "created_by_ref": self.author.id,
            },
        )


class Author(BaseModel):
    """
    Represent an Author organization in OpenCTI.
    """

    def __init__(self, name: str = None, description: str = None):
        identity_class = "organization"

        self.id = PyCTIIdentity.generate_id(name, identity_class)
        self.name = name
        self.description = description
        self.identity_class = identity_class

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=self.id,
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
        )


class Directory(BaseModel):
    """
    Represent a Directory observable in OpenCTI.
    """

    def __init__(
        self, path: str = None, author: Author = None, object_marking_refs=None
    ):
        self.id = None  # placeholder for stix2 ID generation
        self.path = path
        self.author = author

    def to_stix2_object(self) -> stix2.Directory:
        return stix2.Directory(
            path=self.path,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class DomainName(BaseModel):
    """
    Represent a DomainName observable in OpenCTI.
    """

    def __init__(self, value=None, author=None, object_marking_refs=None):
        if not is_domain(value):
            raise ValueError("Invalid DomainName value")

        self.id = None  # placeholder for stix2 ID generation
        self.value = value
        self.author = author

    def to_stix2_object(self) -> stix2.DomainName:
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
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
        name: str = None,
        hashes: dict = None,
        author: Author = None,
        object_marking_refs=None,
    ):
        self.id = None  # placeholer for stix2 ID generation
        self.name = name
        self.hashes = hashes
        self.author = author

    def to_stix2_object(self) -> stix2.File:
        return stix2.File(
            name=self.name,
            hashes=self.hashes,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class Hostname(BaseModel):
    """
    Represent a Hostname observable in OpenCTI.
    """

    def __init__(self, value=None, author=None, object_marking_refs=None):
        self.id = None  # placeholder for stix2 ID generation
        self.value = value
        self.author = author

    def to_stix2_object(self) -> PyCTIObservableHostname:
        # PyCTIObservableHostname is an extension of the STIX2.1 as the spec doesn't implement Hostname observables
        return PyCTIObservableHostname(
            value=self.value,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class IPv4(BaseModel):
    """
    Represent a IPv4 observable in OpenCTI.
    """

    def __init__(self, value=None, author=None, object_marking_refs=None):
        if not is_ipv4(value):
            raise ValueError("Invalid IPv4 address value")

        self.id = None  # placeholder for stix2 ID generation
        self.value = value
        self.author = author

    def to_stix2_object(self) -> stix2.IPv4Address:
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class IPv6(BaseModel):
    """
    Represent a IPv6 observable in OpenCTI.
    """

    def __init__(self, value=None, author=None, object_marking_refs=None):
        if not is_ipv6(value):
            raise ValueError("Invalid IPv6 address value")

        self.id = None  # placeholder for stix2 ID generation
        self.value = value
        self.author = author

    def to_stix2_object(self) -> stix2.IPv6Address:
        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
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
        name: str = None,
        description: str = None,
        source: str = None,
        severity: str = None,
        author: Author = None,
        created_at: datetime.datetime = None,
        updated_at: datetime.datetime = None,
        object_marking_refs=None,
        external_references=None,
    ):
        self.id = PyCTIIncident.generate_id(name, created_at)
        self.name = name
        self.description = description
        self.source = source
        self.severity = severity
        self.author = author
        self.created_at = created_at
        self.updated_at = updated_at

    def to_stix2_object(self) -> stix2.Incident:
        return stix2.Incident(
            id=self.id,
            created=self.created_at,
            name=self.name,
            description=self.description,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            created_by_ref=self.author.id,
            # external_references=[
            # {
            #     "source_name": self.helper.connect_name,
            #     "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.url_id}/summary",
            #     "external_id": alert.url_id,
            # }
            # ],
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
        name: str = None,
        description: str = None,
        value: str = None,
        pattern: str = None,
        pattern_type: str = None,
        x_opencti_score: int = None,
        author: Author = None,
        created_at: datetime.datetime = None,
        updated_at: datetime.datetime = None,
        object_marking_refs=None,
        external_references=None,
    ):
        self.id = PyCTIIndicator.generate_id(value)
        self.name = name
        self.description = description
        self.value = value
        self.pattern = pattern
        self.x_opencti_score = x_opencti_score
        self.author = author
        self.created_at = created_at
        self.updated_at = updated_at

    def to_stix2_object(self) -> stix2.Indicator:
        return stix2.Indicator(
            id=PyCTIIndicator.generate_id(self.value),
            created_by_ref=self.author.id,
            created=self.created_at,
            modified=self.updated_at,
            name=self.name,
            pattern=self.pattern,
            description=self.description,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right marking
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_score": self.x_opencti_score,
                "detection": True,
            },
        )


class Sighting(BaseModel):
    """
    Represent a Sighting event in OpenCTI.
    """

    def __init__(
        self,
        source: Author = None,
        target: Indicator = None,
        first_seen_at: datetime.datetime = None,
        last_seen_at: datetime.datetime = None,
        x_opencti_negative: bool = False,
        object_marking_refs=None,
        external_references=None,
    ):
        self.id = PyCTISighting.generate_id(
            source.id,
            target.id,
            first_seen_at,
            first_seen_at,  # using same date twice avoids duplication
        )
        self.source = source
        self.target = target
        self.first_seen_at = first_seen_at
        self.last_seen_at = last_seen_at
        self.x_opencti_negative = x_opencti_negative

    def to_stix2_object(self) -> stix2.Sighting:
        return stix2.Sighting(
            id=self.id,
            first_seen=self.first_seen_at,
            last_seen=self.last_seen_at,
            sighting_of_ref=self.target.id,
            where_sighted_refs=self.source.id,
            count=1,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            # external_references=[
            #     {
            #         "source_name": "HarfangLab - Security Events",
            #         "url": f"{self.harfanglab_url}/security-event/{new_alert_built['url_id']}/summary",
            #         "external_id": new_alert_built["url_id"],
            #     }
            # ],
            custom_properties={
                "x_opencti_negative": self.x_opencti_negative,
            },
        )


class Url(BaseModel):
    """
    Represent a URL observable in OpenCTI.
    """

    def __init__(self, value=None, author=None, object_marking_refs=None):
        self.id = None  # placeholder for stix2 ID generation
        self.value = value
        self.author = author

    def to_stix2_object(self) -> stix2.URL:
        return stix2.URL(
            value=self.value,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )


class UserAccount(BaseModel):
    """
    Represent a UserAccount observable in OpenCTI.
    """

    def __init__(self, account_login=None, author=None, object_marking_refs=None):
        self.id = None  # placeholder for stix2 ID generation
        self.account_login = account_login
        self.author = author

    def to_stix2_object(self) -> stix2.UserAccount:
        return stix2.UserAccount(
            account_login=self.account_login,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            custom_properties={
                "created_by_ref": self.author.id,
            },
        )
