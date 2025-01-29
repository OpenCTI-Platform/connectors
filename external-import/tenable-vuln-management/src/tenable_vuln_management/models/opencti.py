"""
Define a set of classes representing different entities and observables within OPenCTI.
Each entity (e.g., `Author`, `System`, `Vulnerability`, etc.) corresponds to an object that can be converted into
STIX 2.0 format.

These entities are designed to be frozen Pydantic models, ensuring immutability post-instantiation.

Classes:
    - BaseEntity: Abstract base class for all entities. Provides common attributes and methods
    such as the generation of STIX 2 object representation and unique IDs.
    - Author: Represents an identity, typically an organization, involved in reporting a threat.
    - System: Represents a system or device, such as a network device or host.
    - Observable: Base class for observables, which are characteristics associated with entities like
    systems or assets.
    - MACAddress: Represents a MAC address observable.
    - IPAddress: Represents an IP address observable, with support for IPv4 and IPv6.
    - DomainName: Represents a domain name observable.
    - Hostname: Represents a hostname observable.
    - Software: Represents software installed on a system, usually targeted by a vulnerability.
    - OperatingSystem: Represents an operating system installed on a system.
    - Vulnerability: Represents a vulnerability, including details like CVSS score and severity.
    - RelatedToRelationship: Represents relationships between entities, specifically indicating
    that one entity is related to another.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Literal, Optional

import stix2
import validators
from pycti import CustomObservableHostname as PyCTIHostname
from pycti import Identity as PyCTIIdentity
from pycti import StixCoreRelationship as PyCTIRelationship
from pycti import Vulnerability as PyCTIVulnerability
from pydantic import Field, PrivateAttr, field_validator

from .common import FrozenBaseModelWithoutExtra, make_validator


class BaseEntity(FrozenBaseModelWithoutExtra):
    _stix2_representation: Optional[Any] = PrivateAttr(None)
    _id: Any = PrivateAttr(None)

    def model_post_init(self, context__: Any) -> None:
        """
        Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

        Notes:
            This allows a last modification of the pydantic Model before it is eventually frozen.

        Args:
            context__(Any): The pydantic context used by pydantic framework.

        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]
        """
        self._stix2_representation = self.to_stix2_object()
        self._id = self._stix2_representation["id"]

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct stix object (usually from stix2 python lib objects)"""
        ...

    @property
    def id(self):
        return self._id


class Author(BaseEntity):
    """Represents an author identity, typically an organization."""

    name: str = Field(..., description="Name of the author.", min_length=1)
    description: Optional[str] = Field(None, description="Description of the author.")
    contact_information: Optional[str] = Field(
        None, description="Contact information for the author."
    )
    confidence: Optional[int] = Field(
        None, description="Author confidence level", ge=0, le=100
    )
    x_opencti_organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(None, description="Open CTI Type of the author.")
    x_opencti_reliability: Optional[str] = Field(
        None, description="Open CTI Reliability of the author."
    )
    x_opencti_aliases: Optional[list[str]] = Field(
        None, description="Open CTI Aliases of the author."
    )

    def to_stix2_object(self):
        if self._stix2_representation is not None:
            return self._stix2_representation
        identity_class = "organization"
        return stix2.Identity(
            id=PyCTIIdentity.generate_id(identity_class=identity_class, name=self.name),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            contact_information=self.contact_information,
            confidence=self.confidence,
            # unused
            created=None,
            modified=None,
            created_by_ref=None,
            object_marking_refs=None,
            roles=None,
            sectors=None,
            revoked=None,
            labels=None,
            lang=None,
            external_references=None,
            # customs
            allow_custom=True,
            x_opencti_organization_type=self.x_opencti_organization_type,
            x_opencti_reliability=self.x_opencti_reliability,
            x_opencti_aliases=self.x_opencti_aliases,
        )


class System(BaseEntity):
    """Represents a system identity, such as a network device or a host."""

    name: str = Field(..., description="Name of the system.", min_length=1)
    author: Optional[Author] = Field(
        None, description="The Author reporting this System."
    )
    created: Optional[datetime] = Field(
        None, description="Creation timestamp of the system."
    )
    modified: Optional[datetime] = Field(
        None, description="Last modification timestamp of the system."
    )
    description: Optional[str] = Field(None, description="Description of the system.")
    object_marking_refs: Optional[list[Any]] = Field(
        None,
        description="References for object marking, "
        "usually TLP:xxx objects or their marking ids",
    )

    def to_stix2_object(self) -> Any:
        if self._stix2_representation is not None:
            return self._stix2_representation
        identity_class = "system"
        return stix2.Identity(
            id=PyCTIIdentity.generate_id(identity_class=identity_class, name=self.name),
            identity_class=identity_class,
            name=self.name,
            created_by_ref=self.author.id if self.author is not None else None,
            created=self.created,
            modified=self.modified,
            description=self.description,
            object_marking_refs=self.object_marking_refs,
            # unused
            confidence=None,
            roles=None,
            sectors=None,
            contact_information=None,
            revoked=None,
            labels=None,
            lang=None,
            external_references=None,
            allow_custom=False,
        )


class Observable(BaseEntity):
    """Represents observables associated with a system or an asset."""

    object_marking_refs: Optional[list[Any]] = Field(
        None, description="References for object marking."
    )
    author: Optional[Author] = Field(
        None, description="The Author reporting this Observable."
    )

    @abstractmethod
    def to_stix2_object(self) -> Any: ...


class MACAddress(Observable):
    """Represents a MAC address observable."""

    value: str = Field(..., description="The MAC address value.")
    __value_validator = field_validator("value", mode="after")(
        make_validator("value", validators.mac_address)
    )

    def to_stix2_object(self) -> Any:
        return stix2.MACAddress(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class IPAddress(Observable):
    """Represents an IP address observable, usually linked to an Infrastructure."""

    value: str = Field(..., description="The IP address value.")
    version: Literal["v4", "v6"] = Field(..., description="The IP version.")
    resolves_to_mac_addresses: Optional[list[MACAddress]] = Field(
        None, description="the Mac Addresses it resolves to."
    )
    __value_validator = field_validator("value", mode="after")(
        make_validator("value", {"or": [validators.ipv4, validators.ipv6]})
    )

    def to_stix2_object(self) -> Any:
        builders = {
            "v4": stix2.IPv4Address,
            "v6": stix2.IPv6Address,
        }
        return builders[self.version](
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            resolves_to_refs=(
                [mac_address.id for mac_address in self.resolves_to_mac_addresses]
                if self.resolves_to_mac_addresses
                else None
            ),
            # unused
            belongs_to_refs=None,  # 'autonomous system' id only
            # customs
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class DomainName(Observable):
    """Represents a domain name observable."""

    value: str = Field(..., description="The domain name value.", min_length=1)
    resolves_to_ips: Optional[list[IPAddress]] = Field(
        None, description="IP addresses it resolves to."
    )
    resolves_to_domain_names: Optional[list["DomainName"]] = Field(
        None, description="the domain names it resolves to."
    )

    __value_validator = field_validator("value", mode="after")(
        make_validator("value", validators.domain)
    )

    def to_stix2_object(self) -> Any:
        resolves_to_objects = (
            self.resolves_to_ips if self.resolves_to_ips is not None else []
        ) + (
            self.resolves_to_domain_names
            if self.resolves_to_domain_names is not None
            else []
        )
        resolves_to_ref_ids = [item.id for item in resolves_to_objects]
        return stix2.DomainName(
            value=self.value,
            # 'ipv4-addr', 'ipv6-addr', 'domain-name' ids only
            resolves_to_refs=resolves_to_ref_ids if resolves_to_ref_ids else None,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class Hostname(Observable):
    """Represents a hostname observable."""

    value: str = Field(..., description="The hostname.", min_length=1)
    __value_validator = field_validator("value", mode="after")(
        make_validator("value", validators.hostname)
    )

    def to_stix2_object(self) -> Any:
        return PyCTIHostname(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class Software(Observable):
    """Represents software associated with a system."""

    name: str = Field(..., description="Name of the software.", min_length=1)
    cpe: str = Field(
        ..., description="Common Platform Enumeration (CPE) identifier.", min_length=1
    )
    vendor: str = Field(..., description="The Software vendor Name", min_length=1)

    __value_validator = field_validator("cpe", mode="after")(
        make_validator("cpe", lambda v: v.startswith("cpe:"))
    )

    def to_stix2_object(self) -> Any:
        return stix2.Software(
            name=self.name,
            cpe=self.cpe,
            vendor=self.vendor,
            object_marking_refs=self.object_marking_refs,
            # unused
            swid=None,  # see https://csrc.nist.gov/projects/Software-Identification-SWID
            languages=None,
            version=None,
            # custom
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class OperatingSystem(Observable):
    """Represents one of the operating system installed on a system."""

    name: str = Field(..., description="Name of the Operating system.", min_length=1)

    def to_stix2_object(self) -> Any:
        return stix2.Software(
            name=self.name,
            object_marking_refs=self.object_marking_refs,
            # unused
            cpe=None,
            vendor=None,
            swid=None,  # see https://csrc.nist.gov/projects/Software-Identification-SWID
            languages=None,
            version=None,
            # custom
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class Vulnerability(BaseEntity):
    """Represents a vulnerability entity."""

    author: Optional[Author] = Field(
        ..., description="The Author reporting this Vulnerability."
    )
    created: datetime = Field(
        ..., description="Creation datetime of the vulnerability."
    )
    modified: datetime = Field(
        ..., description="Last modification datetime of the vulnerability."
    )
    name: str = Field(..., description="Name of the vulnerability.", min_length=1)
    description: str = Field(..., description="Description of the vulnerability.")
    confidence: Optional[int] = Field(
        None, description="Confidence level of the vulnerability.", ge=0, le=100
    )
    object_marking_refs: Optional[list[Any]] = Field(
        None,
        description="References for object marking, "
        "usually TLP:xxx objects or their marking ids",
    )
    cvss3_score: Optional[float] = Field(
        None, description="The CVSS v3 base score.", ge=0, le=10
    )
    cvss3_severity: Optional[
        Literal[
            "UNKNOWN",
            "Unknown",
            "LOW",
            "Low",
            "MEDIUM",
            "Medium",
            "HIGH",
            "High",
            "CRITICAL",
            "Critical",
        ]
    ] = Field(None, description="CVSS3 Severity")
    cvss3_attack_vector: Optional[
        Literal[
            "NETWORK",
            "N",
            "Network",
            "ADJACENT",
            "A",
            "Adjacent",
            "LOCAL",
            "L",
            "Local",
            "PHYSICAL",
            "P",
            "Physical",
        ]
    ] = Field(None, description="CVSS3 Attack vector (AV)")
    cvss3_integrity_impact: Optional[
        Literal["NONE", "N", "None", "LOW", "L", "Low", "HIGH", "H", "High"]
    ] = Field(None, description="CVSS3 Integrity impact (I)")
    cvss3_availability_impact: Optional[
        Literal["NONE", "N", "None", "LOW", "L", "Low", "HIGH", "H", "High"]
    ] = Field(None, description="CVSS3 Availability impact (A)")
    cvss3_confidentiality_impact: Optional[
        Literal["NONE", "N", "None", "LOW", "L", "Low", "HIGH", "H", "High"]
    ] = Field(None, description="CVSS3 Confidentiality impact (C)")

    def to_stix2_object(self) -> Any:
        return stix2.Vulnerability(
            id=PyCTIVulnerability.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id if self.author else None,
            created=self.created,
            modified=self.modified,
            description=self.description,
            confidence=self.confidence,
            object_marking_refs=self.object_marking_refs,
            # unused
            lang=None,
            external_references=None,
            # custom
            allow_custom=True,
            x_opencti_aliases=[],
            x_opencti_cvss_base_score=self.cvss3_score,
            x_opencti_cvss_base_severity=self.cvss3_severity,
            x_opencti_cvss_attack_vector=self.cvss3_attack_vector,
            x_opencti_cvss_integrity_impact=self.cvss3_integrity_impact,
            x_opencti_cvss_availability_impact=self.cvss3_availability_impact,
            x_opencti_cvss_confidentiality_impact=self.cvss3_confidentiality_impact,
        )


class BaseRelationship(BaseEntity):
    """Represents a Base relationship."""

    author: Author = Field(
        ..., description="Reference to the author that reported this relationship."
    )
    created: Optional[datetime] = Field(
        None, description="Creation timestamp of the relationship."
    )
    modified: Optional[datetime] = Field(
        None, description="Last modification timestamp of the relationship."
    )
    description: Optional[str] = Field(
        None, description="Description of the relationship."
    )
    source_ref: str = Field(
        ..., description="Reference to the source entity of the relationship."
    )
    target_ref: str = Field(
        ..., description="Reference to the target entity of the relationship."
    )
    start_time: Optional[datetime] = Field(
        None, description="Start time of the relationship in ISO 8601 format."
    )
    stop_time: Optional[datetime] = Field(
        None, description="End time of the relationship in ISO 8601 format."
    )
    confidence: Optional[int] = Field(
        None, description="Confidence level regarding the relationship.", ge=0, le=100
    )
    object_marking_refs: Optional[list[Any]] = Field(
        None,
        description="References for object marking, "
        "usually TLP:xxx objects or their marking ids",
    )
    external_references: Optional[list[Any]] = Field(
        None,
        description="External references",
    )

    @abstractmethod
    def to_stix2_object(self) -> Any: ...

    def _common_stix2_args(self) -> dict[str, Any]:
        return {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            # optional
            "created_by_ref": self.author.id if self.author else None,
            "created": self.created,
            "modified": self.modified,
            "description": self.description,
            "start_time": self.start_time,
            "stop_time": self.stop_time,
            "confidence": self.confidence,
            "object_marking_refs": self.object_marking_refs,
            "external_references": self.external_references,
        }


class RelatedToRelationship(BaseRelationship):
    """Represents a relationship indicating that one object is related to another. Mainly used in Observable use cases.
    Notes:
        The Relationship id is determinist.
    """

    def to_stix2_object(self) -> Any:
        return stix2.Relationship(
            id=PyCTIRelationship.generate_id(
                relationship_type="related-to",
                source_ref=self.source_ref,
                target_ref=self.target_ref,
                start_time=self.start_time,
                stop_time=self.stop_time,
            ),
            relationship_type="related-to",
            **self._common_stix2_args(),
        )


class HasRelationship(BaseRelationship):
    """Represents a relationship indicating that one object is related to another with "HAS".

    Mainly used between (:System)-[:HAS]->(:Vulnerability) and (:Software)-[:Has]->(:Vulnerability)

    Notes:
        The Relationship id is determinist and excludes the stop_time from the hash as it might be updated.
    """

    def to_stix2_object(self) -> Any:
        return stix2.Relationship(
            id=PyCTIRelationship.generate_id(
                relationship_type="has",
                source_ref=self.source_ref,
                target_ref=self.target_ref,
                start_time=self.start_time,
            ),
            relationship_type="has",
            **self._common_stix2_args(),
        )
