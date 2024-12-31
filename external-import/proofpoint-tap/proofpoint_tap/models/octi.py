"""Define the OpenCTI models."""

from abc import abstractmethod
from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, PrivateAttr

# if TYPE_CHECKING:


class BaseModelWithoutExtra(BaseModel):
    """Represent a Pydantic BaseModel where non explicitly define fields are forbidden."""

    model_config = ConfigDict(
        extra="forbid",
    )

    def __hash__(self) -> int:
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: Any) -> bool:
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()


class BaseEntity(BaseModelWithoutExtra):
    """Base class to implement common attributes and methods for all entities."""

    _stix2_representation: Optional[Any] = PrivateAttr(None)
    _id: str = PrivateAttr(None)

    def model_post_init(
        self, context__: Any
    ) -> None:  # pylint: disable=unused-argument
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

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
    def to_stix2_object(self) -> stix2.v21._STIXBase21:  # noqa: W0212
        """Make stix object (usually from stix2 python lib objects)."""

    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        return self._id


class ExternalReference(BaseModelWithoutExtra):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
        ..., description="The name of the source of the external reference."
    )
    description: Optional[str] = Field(
        None, description="Description of the external reference."
    )
    url: Optional[str] = Field(None, description="URL of the external reference.")

    def to_stix2_object(self) -> Any:
        """Make stix object."""
        return stix2.ExternalReference(
            source_name=self.source_name,
            description=self.description,
            url=self.url,
            # unused
            external_id=None,
            hashes=None,
        )


class Author(BaseEntity):
    """Represent an author.

    Warning:
        This class cannot be used directly, it must be subclassed.

    """

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        raise NotImplementedError()


class Organization(BaseEntity):
    """Represent an organization."""

    name: str = Field(..., description="Name of the organization.", min_length=1)
    description: Optional[str] = Field(
        None, description="Description of the organization."
    )
    confidence: Optional[int] = Field(
        None, description="Organization confidence level", ge=0, le=100
    )
    author: Optional[Author] = Field(None, description="Author of the organization.")
    labels: Optional[list[str]] = Field(None, description="Labels of the organization.")
    markings: Optional[list[stix2.TLPMarking]] = Field(
        None, description="Markings of the organization."
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None, description="External references of the organization."
    )
    contact_information: Optional[str] = Field(
        None, description="Contact information for the organization."
    )
    organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(None, description="Open CTI Type of the organization.")
    reliability: Optional[str] = Field(
        None, description="Open CTI Reliability of the organization."
    )
    aliases: Optional[list[str]] = Field(
        None, description="Aliases of the organization."
    )

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        identity_class = "organization"
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=identity_class, name=self.name
            ),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            contact_information=self.contact_information,
            confidence=self.confidence,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking["id"] for marking in self.markings or []],
            created_by_ref=self.author.id if self.author else None,
            # unused
            created=None,
            modified=None,
            roles=None,
            sectors=None,
            revoked=None,
            labels=None,
            lang=None,
            # customs
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_organization_type=self.organization_type,
                x_opencti_reliability=self.reliability,
                x_opencti_aliases=self.aliases,
            ),
        )


class OrganizationAuthor(Author, Organization):
    """Represent an organization author."""


class Campaign(BaseEntity):
    """Represent a campaign."""

    name: str = Field(..., description="Name of the campaign.", min_length=1)
    description: str = Field(..., description="Description of the campaign.")
    labels: Optional[list[str]] = Field(None, description="Labels of the campaign.")
    markings: Optional[list[stix2.TLPMarking]] = Field(
        None, description="Markings of the campaign."
    )
    author: Optional[Author] = Field(None, description="Author of the campaign.")
    external_references: Optional[list[ExternalReference]] = Field(
        None, description="External references of the campaign."
    )
    first_seen: Optional[AwareDatetime] = Field(
        None, description="First seen date of the campaign."
    )

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Campaign(
            id=pycti.Campaign.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            create_by_ref=self.author.id if self.author is not None else None,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            first_seen=self.first_seen,
            object_marking_refs=[marking["id"] for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            last_seen=None,
            objective=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties=None,
        )


class IntrusionSet(BaseEntity):
    """Represent an intrusion set."""

    name: str = Field(..., description="Name of the intrusion set.", min_length=1)
    description: str = Field(..., description="Description of the intrusion set.")
    labels: Optional[list[str]] = Field(
        None, description="Labels of the intrusion set."
    )
    markings: Optional[list[stix2.TLPMarking]] = Field(
        None, description="Markings of the intrusion set."
    )
    author: Optional[Author] = Field(None, description="Author of the intrusion set.")
    external_references: Optional[list[ExternalReference]] = Field(
        None, description="External references of the intrusion set."
    )

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            create_by_ref=self.author.id if self.author is not None else None,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking["id"] for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            first_seen=None,
            last_seen=None,
            aliases=None,
            goals=None,
            resource_level=None,
            primary_motivation=None,
            secondary_motivations=None,
            personal_motivations=None,
            infrastructure=None,
            attribution=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties=None,
        )


class Malware(BaseEntity):
    """Represent a malware."""

    name: str = Field(..., description="Name of the malware.", min_length=1)
    types: Optional[
        list[
            Literal[
                "adware",
                "backdoor",
                "bootkit",
                "bot",
                "ddos",
                "downloader",
                "dropper",
                "exploit-kit",
                "keylogger",
                "ransomware",
                "remote-access-trojan",
                "resource-exploitation",
                "rogue-security-software",
                "rootkit",
                "screen-capture",
                "spyware",
                "trojan",
                "unknown",
                "virus",
                "webshell",
                "wiper",
                "worm",
            ]
        ]
    ] = Field(None, description="Types of the malware.")
    is_family: Optional[bool] = Field(None, description="Is the malware a family?")
    description: Optional[str] = Field(None, description="Description of the malware.")
    architecture_execution_env: Optional[
        list[
            Literal[
                "alpha", "arm", "ia-64", "mips", "powerpc", "sparc", "x86", "x86-64"
            ]
        ]
    ] = Field(None, description="Architecture execution environment of the malware.")
    implementation_languages: Optional[
        list[
            Literal[
                "applescript",
                "bash",
                "c",
                "c#",
                "c++",
                "go",
                "java",
                "javascript",
                "lua",
                "objective-c",
                "perl",
                "php",
                "powershell",
                "python",
                "ruby",
                "rust",
                "scala",
                "swift",
                "typescript",
                "visual-basic",
                "x86-32",
                "x86-64",
            ]
        ]
    ] = Field(None, description="Implementation languages of the malware.")
    kill_chain_phases: Optional[list[str]] = Field(
        None, description="Kill chain phases of the malware."
    )
    author: Optional[Author] = Field(None, description="Author of the malware.")
    labels: Optional[list[str]] = Field(None, description="Labels of the malware.")
    markings: Optional[list[stix2.TLPMarking]] = Field(
        None, description="Markings of the malware."
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None, description="External references of the malware."
    )

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.Malware(
            id=pycti.Malware.generate_id(name=self.name),
            crate_by_ref=self.author.id if self.author is not None else None,
            name=self.name,
            description=self.description,
            malware_types=self.types,
            is_family=self.is_family,
            architecture_execution_envs=self.architecture_execution_env,
            implementation_languages=self.implementation_languages,
            kill_chain_phases=self.kill_chain_phases,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking["id"] for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            first_seen=None,
            last_seen=None,
            operating_system_refs=None,
            capabilities=None,
            sample_refs=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties=None,
        )


class AttackPattern(BaseEntity):
    """Represent an attack pattern."""

    name: str = Field(..., description="Name of the attack pattern.", min_length=1)
    external_id: Optional[str] = Field(
        None, description="External ID of the attack pattern."
    )
    description: Optional[str] = Field(
        None, description="Description of the attack pattern."
    )
    kill_chain_phases: Optional[list[str]] = Field(
        None, description="Kill chain phases of the attack pattern."
    )
    author: Optional[Author] = Field(None, description="Author of the attack pattern.")
    labels: Optional[list[str]] = Field(
        None, description="Labels of the attack pattern."
    )
    markings: Optional[list[stix2.TLPMarking]] = Field(
        None, description="Markings of the attack pattern."
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None, description="External references of the attack pattern."
    )

    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        return stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(name=self.name),
            crate_by_ref=self.author.id if self.author is not None else None,
            name=self.name,
            description=self.description,
            external_id=self.external_id,
            kill_chain_phases=self.kill_chain_phases,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking["id"] for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            first_seen=None,
            last_seen=None,
            revoked=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
            # customs
            custom_properties=None,
        )


class TargetedOrganization(Organization):
    """Represent a targeted organization."""


class Observable(BaseEntity):
    """Represents observables associated with a system or an asset.

    NOTA BENE: Observables do not need determinitic stix id generation. STIX python lib handles it.
    """

    marking: Optional[list[stix2.TLPMarking]] = Field(
        None, description="References for object marking."
    )
    author: Optional[Author] = Field(
        description="The Author reporting this Observable."
    )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Make stix object."""

    @abstractmethod
    def to_indicator(self) -> stix2.Indicator:
        """Make indicator stix object."""
