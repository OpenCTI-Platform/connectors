"""Define a set of classes representing different entities and observables within OPenCTI.
Each entity (e.g., `Author`, `System`, `Vulnerability`, etc.) corresponds to an object that can be converted into
STIX 2.1 format.

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
that one entity is "related to" another.
- HasRelationShip: Represents relationships between entities, specifically indicating
that one entity "has" another.
"""

import re
from abc import abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable, Generic, Literal, Optional, TypeVar

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
import validators
from cvss import CVSS3  # type: ignore[import-untyped] # cvss does not provide stubs
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

if TYPE_CHECKING:
    from stix2.v21 import _STIXBase21  # type: ignore[import-untyped]

T = TypeVar("T")


class BaseModelWithoutExtra(BaseModel, Generic[T]):
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


def make_validator(
    field_name: str, validator: Callable[..., bool] | dict[str, Any]
) -> Callable[[Any], Any]:
    """Make of field validator to use in pydantic models.

    This version supports simple validator callables and compound validators
    expressed as dictionaries using "and"/"or" logical operations.

    Args:
        field_name(str): name of the validated field. For error message purpose only.
        validator(Callable[..., bool] or dict): A single validator or a compound logical dictionary representing
            "and" or "or" logical validator combinations.

    Returns:
        (Callable[..., Any]): The validator to be used.

    Raises:
        ValueError: if validator call returns False. Note: used with Pydantic field_validator this will finally raise a
            Pydantic ValidationError

    Examples:
        >>> import validators
        >>> my_validator = make_validator("blah", validators.ipv4)
        >>> print(my_validator("127.0.0.1"))
        >>> try: my_validator("whatever"); except ValueError as err: print(err)

        >>> compound_validator = make_validator("blah", {"or": [validators.ipv4, validators.ipv6]})
        >>> print(compound_validator("127.0.0.1"))  # Passes ipv4
        >>> print(compound_validator("::1"))  # Passes ipv6
        >>> try: compound_validator("whatever"); except ValueError as err: print(err)

    References:
        https://docs.pydantic.dev/2.9/examples/validators/ [consulted on September 30th, 2024]

    """

    def evaluate_validator(
        evaluated_validator: Callable[..., bool] | dict[str, Any], value: Any
    ) -> bool:
        """Recursively evaluate validators based on boolean logic in the dictionary format."""
        if isinstance(evaluated_validator, dict):
            # Handling "or" and "and" logical operators
            if "or" in evaluated_validator:
                # Any one of the validators in the list should pass
                return any(
                    evaluate_validator(sub_validator, value)
                    for sub_validator in evaluated_validator["or"]
                )
            if "and" in evaluated_validator:
                # All validators in the list should pass
                return all(
                    evaluate_validator(sub_validator, value)
                    for sub_validator in evaluated_validator["and"]
                )

            raise ValueError(
                f"Unsupported logical operation in validator: {evaluated_validator}"
            )

        # Regular callable validator
        return evaluated_validator(value)

    def _field_validator(value: Any) -> Any:
        if evaluate_validator(validator, value):
            return value
        validator_name = getattr(validator, "__name__", repr(validator))
        message = f"Field: {field_name} with value: {str(value)} does not pass {validator_name} validation."
        raise ValueError(message)

    return _field_validator


class ExternalReference(BaseModelWithoutExtra):  # type: ignore[type-arg]
    # See https://docs.pydantic.dev/2.8/concepts/models/#generic-models
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


class BaseEntity(BaseModelWithoutExtra):  # type: ignore[type-arg]
    # See https://docs.pydantic.dev/2.8/concepts/models/#generic-models
    """Base class to implement common attributes and methods for all entities."""

    _stix2_representation: Optional[Any] = PrivateAttr(None)
    _id: str = PrivateAttr("")

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

    def to_stix2_object(self) -> "_STIXBase21":
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
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation
        identity_class = "system"
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=identity_class, name=self.name
            ),
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
    """Represents observables associated with a system or an asset.

    NOTA BENE: Observables do not need determinitic stix id generation. STIX python lib, handle it.
    """

    object_marking_refs: Optional[list[Any]] = Field(
        None, description="References for object marking."
    )
    author: Author = Field(description="The Author reporting this Observable.")

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Make stix object."""


class MACAddress(Observable):
    """Represents a MAC address observable."""

    value: str = Field(..., description="The MAC address value.")
    __value_validator = field_validator("value", mode="after")(
        make_validator("value", validators.mac_address)
    )

    def to_stix2_object(self) -> Any:
        """Make stix object."""
        return stix2.MACAddress(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_custom=True,
            created_by_ref=self.author.id,
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
        """Make stix object."""
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
        """Make stix object."""
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
            created_by_ref=self.author.id,
        )


class Hostname(Observable):
    """Represents a hostname observable."""

    value: str = Field(..., description="The hostname.", min_length=1)
    __value_validator = field_validator("value", mode="after")(
        make_validator("value", validators.hostname)
    )

    def to_stix2_object(self) -> Any:
        """Make stix object."""
        return pycti.CustomObservableHostname(
            value=self.value,
            object_marking_refs=self.object_marking_refs,
            # customs
            allow_custom=True,
            created_by_ref=self.author.id,
        )


class Software(Observable):
    """Represents software associated with a system."""

    name: str = Field(..., description="Name of the software.", min_length=1)
    cpe: str = Field(
        ..., description="Common Platform Enumeration (CPE) identifier.", min_length=1
    )
    vendor: str = Field(..., description="The Software vendor Name", min_length=1)

    __value_validator = field_validator("cpe", mode="after")(
        make_validator("cpe", lambda v: v.startswith("cpe:") or v.startswith("p-cpe:"))
    )

    def to_stix2_object(self) -> Any:
        """Make stix object."""
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
            created_by_ref=self.author.id,
        )

    @staticmethod
    def parse_cpe_uri(cpe_str: str) -> dict[str, str]:
        """Parse CPE URI following format 1 or 2.3.

        Args:
            cpe_str: the CPE URI

        Returns:
            (dict[str|str]):  {"part": part, "vendor": vendor, "product": product}

        Examples:
            >>> dct = Vulnerability.parse_cpe_uri("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

        """
        supported_patterns = {
            "cpe:/": r"^cpe:/(?P<part>[a-z]):(?P<vendor>[a-zA-Z0-9_\-]+):(?P<product>[a-zA-Z0-9_\-]+)",
            "cpe:2.3": r"^cpe:2\.3:(?P<part>[a-z]+):(?P<vendor>[^:]+):(?P<product>[^:]+)",
            "p-cpe:/": r"^p-cpe:/(?P<part>[a-z]):(?P<vendor>[a-zA-Z0-9_\-]+):(?P<product>[a-zA-Z0-9_\-]+)",
            "p-cpe:2.3": r"^p-cpe:2\.3:(?P<part>[a-z]+):(?P<vendor>[^:]+):(?P<product>[^:]+)",
        }

        for key, supported_pattern in supported_patterns.items():
            if cpe_str.startswith(key):
                match = re.match(pattern=supported_pattern, string=cpe_str)
                if match is not None:
                    return {
                        "part": match.group("part"),
                        "vendor": match.group("vendor"),
                        "product": match.group("product"),
                    }
                raise ValueError("CPE URI is missing mandatory information.")
        raise NotImplementedError(f"Unknown CPE URI format: {cpe_str}")


class OperatingSystem(Observable):
    """Represents one of the operating system installed on a system."""

    name: str = Field(..., description="Name of the Operating system.", min_length=1)

    def to_stix2_object(self) -> Any:
        """Make stix object."""
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
            created_by_ref=self.author.id,
        )


class Vulnerability(BaseEntity):
    """Represents a vulnerability entity."""

    author: Author = Field(..., description="The Author reporting this Vulnerability.")
    created: Optional[datetime] = Field(
        None, description="Creation datetime of the vulnerability."
    )
    modified: Optional[datetime] = Field(
        None, description="Last modification datetime of the vulnerability."
    )
    name: str = Field(..., description="Name of the vulnerability.", min_length=1)
    description: Optional[str] = Field(
        None, description="Description of the vulnerability."
    )
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
        """Make stix object."""
        return stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            created_by_ref=self.author.id,
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

    @staticmethod
    def cvss3_severity_from_score(
        score: Optional[float],
    ) -> Literal["Unknown", "Low", "Medium", "High", "Critical"]:
        """Determine the CVSS v3 severity rating based on the CVSS score.

        This function maps the CVSS score to its qualitative severity rating
        as defined by the CVSS v3 specification (Table 14).

        Severity ratings and corresponding score ranges:
          - Unknown: 0.0
          - Low: 0.1 - 3.9
          - Medium: 4.0 - 6.9
          - High: 7.0 - 8.9
          - Critical: 9.0 - 10.0

        Args:
            score (float): The CVSS v3 score, which should be in the range 0.0 to 10.0.

        Returns:
            str: The severity rating ("Unknown", "Low", "Medium", "High", or "Critical").

        Raises:
            ValueError: If the score is outside the valid range (0.0 - 10.0).

        References:
            https://www.first.org/cvss/v3.0/specification-document [consulted on September 30th, 2024]

        """
        _score = score or 0.0

        match _score:
            case 0.0:
                return "Unknown"
            case _ if 0.1 <= _score <= 3.9:
                return "Low"
            case _ if 4.0 <= _score <= 6.9:
                return "Medium"
            case _ if 7.0 <= _score <= 8.9:
                return "High"
            case _ if 9.0 <= _score <= 10.0:
                return "Critical"
            case _:
                raise ValueError("Invalid CVSS score. It must be between 0.0 and 10.0.")

    @staticmethod
    def parse_cvss3_vector(vector: str) -> CVSS3:
        """Parse a CVSS v3 vector string into a CVSS3 object."""
        if not vector.startswith("CVSS:3"):
            # missing prefix : we try to add 3.0 one
            vector = f"CVSS:3.0/{vector}"
        return CVSS3(vector=vector)

    @staticmethod
    def convert_cvss2_to_cvss3(cvss2_vector: str) -> CVSS3:
        """Convert a CVSS v2 vector to a CVSS v3 one."""
        mapping = {
            "AV": {"N": "N", "A": "A", "L": "P"},
            "AC": {"L": "L", "M": "H", "H": "H"},
            "Au": {"N": "N", "S": "L", "M": "H"},
            "C": {"N": "N", "P": "L", "C": "H"},
            "I": {"N": "N", "P": "L", "C": "H"},
            "A": {"N": "N", "P": "L", "C": "H"},
        }
        cvss2_parts = dict(item.split(":") for item in cvss2_vector.split("/"))
        cvss3_parts = {
            "AV": mapping["AV"].get(cvss2_parts["AV"], "N"),
            "AC": mapping["AC"].get(cvss2_parts["AC"], "L"),
            "PR": mapping["Au"].get(cvss2_parts["Au"], "N"),
            "UI": "N",  # Default, since CVSSv2 lacks UI
            "S": "U",  # Default, since CVSSv2 lacks Scope
            "C": mapping["C"].get(cvss2_parts["C"], "N"),
            "I": mapping["I"].get(cvss2_parts["I"], "N"),
            "A": mapping["A"].get(cvss2_parts["A"], "N"),
        }

        cvss3_vector = "/".join(f"{key}:{value}" for key, value in cvss3_parts.items())
        return Vulnerability.parse_cvss3_vector(cvss3_vector)


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
    source_ref: BaseEntity = Field(
        ..., description="Reference to the source entity of the relationship."
    )
    target_ref: BaseEntity = Field(
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
    external_references: Optional[list[ExternalReference]] = Field(
        None,
        description="External references",
    )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Make stix object."""

    def _common_stix2_args(self) -> dict[str, Any]:
        return {
            "source_ref": self.source_ref.id,
            "target_ref": self.target_ref.id,
            # optional
            "created_by_ref": self.author.id,
            "created": self.created,
            "modified": self.modified,
            "description": self.description,
            "start_time": self.start_time,
            "stop_time": self.stop_time,
            "confidence": self.confidence,
            "object_marking_refs": self.object_marking_refs,
            "external_references": (
                [ref.to_stix2_object() for ref in self.external_references]
                if self.external_references
                else None
            ),
        }


class RelatedToRelationship(BaseRelationship):
    """Represents a relationship indicating that one object is related to another. Mainly used in Observable use cases.

    Notes:
        The Relationship id is determinist.

    """

    def to_stix2_object(self) -> Any:
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type="related-to",
                source_ref=self.source_ref.id,
                target_ref=self.target_ref.id,
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
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type="has",
                source_ref=self.source_ref.id,
                target_ref=self.target_ref.id,
                start_time=self.start_time,
            ),
            relationship_type="has",
            **self._common_stix2_args(),
        )
