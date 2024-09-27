import datetime
from abc import abstractmethod
from typing import Any, Literal, Optional

import stix2
from pycti import CustomObservableHostname as PyCTIHostname
from pycti import Identity as PyCTIIdentity
from pycti import StixCoreRelationship as PyCTIRelationship
from pycti import Vulnerability as PyCTIVulnerability
from pydantic import Field

from .common import FrozenBaseModelWithoutExtra


class BaseEntity(FrozenBaseModelWithoutExtra):
    def __init__(self, **kwargs):
        self._stix2_representation = self.to_stix2_object()
        self.id = self._stix2_representation["id"]
        super().__init__(**kwargs)

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct stix object (usually from stix2 python lib objects)"""
        ...


class Author(BaseEntity):
    """Represents an author identity, typically an organization."""

    name: str = Field(..., description="Name of the author.")
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
            created_by_ref=self.created_by_ref,
            description=self.description,
            object_marking_refs=self.object_marking_refs,
            contact_information=self.contact_information,
            confidence=self.confidence,
            # unused
            created=None,
            modified=None,
            roles=None,  # type: list[str] | None
            sectors=None,  # type: list[str] | None # in stix2 industry sectors list
            revoked=None,  # type: bool | None
            labels=None,  # type: list[str] | None
            lang=None,  # type: str | None
            external_references=None,  # type: list[dict] | None
            # customs
            allow_custom=True,
            x_opencti_organization_type=self.x_opencti_organization_type,
            x_opencti_reliability=self.x_opencti_reliability,
            x_opencti_aliases=self.x_opencti_aliases,
        )


class System(BaseEntity):
    """Represents a system identity, such as a network device or a host."""

    name: str = Field(..., description="Name of the system.")
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
            confidence=None,  # type: int | None  # from 0 to 100
            roles=None,  # type: list[str] | None
            sectors=None,  # type: list[str] | None # in stix2 industry sectors list
            contact_information=None,  # type: str | None
            revoked=None,  # type: bool | None
            labels=None,  # type: list[str] | None
            lang=None,  # type: str | None
            external_references=None,  # type: list[dict] | None
            allow_custom=False,
        )


class Observable(BaseEntity):
    """Represents observables associated with a system or an asset."""

    object_marking_refs: list[str] = Field(
        ..., description="References for object marking."
    )
    author: Optional[Author] = Field(
        None, description="The Author reporting this Observable."
    )

    @abstractmethod
    def to_stix2_object(self) -> Any: ...


class MACAddress(Observable):
    """Represents a MAC address observable."""

    value: str = Field(..., description="The MAC address value.")

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

    def to_stix2_object(self) -> Any:
        builders = {
            "v4": stix2.IPv4Address,
            "v6": stix2.IPv6Address,
        }
        return builders[self.version](
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            resolves_to_refs=self.resolves_to_mac_addresses,  # 'mac addresses{ id only
            # unused
            belongs_to_refs=None,  # 'autonomous system' id only
            # customs
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class DomainName(Observable):
    """Represents a domain name observable."""

    value: str = Field(..., description="The domain name value.")
    resolves_to_ips: Optional[list[IPAddress]] = Field(
        None, description="IP addresses it resolves to."
    )
    resolves_to_mac_addresses: Optional[list[MACAddress]] = Field(
        None, description="Mac addresses it resolves to."
    )

    def to_stix2_object(self) -> Any:
        resolves_to_objects = (
            self.resolves_to_ips if self.resolves_to_ips is not None else []
        ) + (
            self.resolves_to_mac_addresses
            if self.resolves_to_mac_addresses is not None
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

    value: str = Field(..., description="The hostname.")

    def to_stix2_object(self) -> Any:
        return PyCTIHostname(
            value=self.values,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_customs=True,
            created_by_ref=self.author.id if self.author else None,
        )


class Software(Observable):
    """Represents software associated with a system."""

    name: str = Field(..., description="Name of the software.")
    cpe: str = Field(..., description="Common Platform Enumeration (CPE) identifier.")
    vendor: str = Field(..., description="The Software vendor Name")

    def to_stix2_object(self) -> Any:
        return stix2.Software(
            name=self.name,
            cpe=self.cpe,
            vendor=self.vendor,
            object_marking_refs=self.object_marking_refs,
            # unused
            swid=None,  # type: str|None  # see https://csrc.nist.gov/projects/Software-Identification-SWID
            languages=None,  # type: list[str]|None
            version=None,  # type: str | None
            # custom
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class OperatingSystem(Observable):
    """Represents one of the operating system installed on a system."""

    name: str = Field(..., description="Name of the Operating system.")

    def to_stix2_object(self) -> Any:
        return stix2.Software(
            name=self.name,
            object_marking_refs=self.object_marking_refs,
            # unused
            cpe=None,
            vendor=None,
            swid=None,  # type: str|None  # see https://csrc.nist.gov/projects/Software-Identification-SWID
            languages=None,  # type: list[str]|None
            version=None,  # type: str | None
            # custom
            allow_custom=True,
            created_by_ref=self.author.id if self.author else None,
        )


class Vulnerability(BaseEntity):
    """Represents a vulnerability entity."""

    author: Optional[Author] = Field(
        ..., description="The Author reporting this Vulnerability."
    )
    created: datetime.datetime = Field(
        ..., description="Creation datetime of the vulnerability."
    )
    modified: datetime.datetime = Field(
        ..., description="Last modification datetime of the vulnerability."
    )
    name: str = Field(..., description="Name of the vulnerability.")
    description: str = Field(..., description="Description of the vulnerability.")
    confidence: int = Field(
        ..., description="Confidence level of the vulnerability.", ge=0, le=100
    )
    object_marking_refs: Optional[list[Any]] = Field(
        None,
        description="References for object marking, "
        "usually TLP:xxx objects or their marking ids",
    )

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
        )


class RelatedToRelationship(BaseEntity):
    """Represents a relationship indicating that one object is related to another.

    Notes:
        the Relationship id is determinist and exclude the stop_time from the hash as it might be updated.
    """

    author: Author = Field(
        ..., description="Reference to the author that reported this relationship."
    )
    created: Optional[datetime] = Field(
        None, description="Creation timestamp of the relationship."
    )
    modified: Optional[datetime] = Field(
        None, description="Last modification timestamp of the relationship."
    )
    relationship_type: str = Field(
        "related-to", description="Type of the relationship, defaults to 'related-to'."
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

    def to_stix2_object(self) -> Any:
        return stix2.Relationship(
            id=PyCTIRelationship.generate_id(
                relationship_type="related-to",
                source_ref=self.source_ref,
                target_ref=self.target_ref,
                start_time=self.start_time,
            ),
            relationship_type="related-to",
            source_ref=self.source_ref,
            target_ref=self.target_ref,
            # optional
            created_by_ref=self.author.id if self.author else None,
            created=self.created,
            modified=self.modified,
            description=self.description,
            start_time=self.start_time,
            stop_time=self.stop_time,
            confidence=self.confidence,
            object_marking_refs=self.object_marking_refs,
        )
