from abc import abstractmethod
from datetime import datetime
from typing import Any, Literal, Optional

import pycti
import stix2
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, PrivateAttr
from src.connector.models.intelligence import asn_regex


class Converter(BaseModel):
    """
    Base class for OpenCTI models.
    OpenCTI models are extended implementations of STIX 2.1 specification.
    All OpenCTI models implement `to_stix2_object` method to return a validated and formatted STIX 2.1 dict.
    """

    model_config = ConfigDict(extra="forbid")

    _stix2_representation: Optional[Any] = PrivateAttr(default=None)
    _id: str = PrivateAttr(default=None)

    def model_post_init(self, context__) -> None:
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
        self._id = self._stix2_representation.get("id")

    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        return self._id

    @property
    def stix2_representation(self) -> Optional[dict]:
        """Return the STIX 2.1 object representation of the model."""
        if self._stix2_representation is None:
            self._stix2_representation = self.to_stix2_object()
        return self._stix2_representation

    @abstractmethod
    def to_stix2_object(self) -> dict:
        """
        Abstract method to construct the corresponding STIX 2.1 object
        (usually from stix2 python lib objects)
        """


class Author(Converter):
    """Represent an author identity, typically an organization."""

    name: str = Field(
        description="Reference to the name of the author.",
    )
    identity_class: Optional[str] = Field(
        default="organization",
        description="Reference to the identity class of the author (organization).",
    )
    organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(
        default=None,
        description="Reference to Open CTI Type of the author.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Reference to the description of the author.",
    )

    def to_stix2_object(self) -> stix2.Identity:
        """Converted to Stix 2.1 object."""
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=self.identity_class, name=self.name
            ),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
            custom_properties={
                "x_opencti_organization_type": self.organization_type,
                "x_opencti_external_references": [
                    stix2.ExternalReference(
                        source_name="ServiceNow",
                        url="https://www.servicenow.com/",
                        description="Official site of ServiceNow.",
                    )
                ],
            },
        )


class TLPMarking(Converter):
    """Represent a TLP Marking definition."""

    level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        description="The level of the marking.",
    )

    def to_stix2_object(self) -> stix2.MarkingDefinition:
        """Make stix object."""
        mapping = {
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[self.level]


class ExternalReference(Converter):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
        description="The name of the source of the external reference.",
    )
    url: Optional[str] = Field(
        default=None,
        description="URL pointing to the external resource or associated documentation.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Short description of the external reference.",
    )
    external_id: Optional[str] = Field(
        default=None,
        description="Source-specific external identifier.",
    )

    def to_stix2_object(self) -> stix2.ExternalReference:
        """Make stix object."""
        return stix2.ExternalReference(
            source_name=self.source_name,
            description=self.description,
            url=self.url,
            external_id=self.external_id,
        )


class AttackPattern(Converter):
    """Represent an Attack Pattern Object."""

    name: str = Field(description="Name of the attack pattern.", min_length=1)
    external_id: Optional[str] = Field(
        default=None,
        description="External ID of the attack pattern.",
    )
    aliases: Optional[str] = Field(
        default=None,
        description="Aliases of the attack pattern.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of the attack pattern.",
    )
    author: Optional[Author] = Field(
        description="Author of the attack pattern.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        default=None,
        description="Markings of the attack pattern.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        default=None,
        description="An external link to the parent security incident data.",
    )

    def to_stix2_object(self) -> stix2.AttackPattern:
        """Make stix object."""
        return stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(
                name=self.name, x_mitre_id=self.external_id
            ),
            created_by_ref=self.author.id,
            name=self.name,
            description=self.description,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                external_references.to_stix2_object()
                for external_references in self.external_references or []
            ],
            aliases=self.aliases,
            custom_properties={
                "x_mitre_id": self.external_id,
            },
        )


class IntrusionSet(Converter):
    """Represent an Intrusion Set Object."""

    name: str = Field(description="Name of the attack pattern.", min_length=1)
    aliases: Optional[str] = Field(
        default=None,
        description="Aliases of the attack pattern.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of the attack pattern.",
    )
    author: Optional[Author] = Field(
        description="Author of the attack pattern.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        default=None,
        description="Markings of the attack pattern.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        default=None,
        description="An external link to the parent security incident data.",
    )

    def to_stix2_object(self) -> stix2.IntrusionSet:
        """Make stix object."""
        return stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(name=self.name),
            created_by_ref=self.author.id,
            name=self.name,
            aliases=self.aliases,
            description=self.description,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_external_references": [
                    external_references.to_stix2_object()
                    for external_references in self.external_references or []
                ],
            },
        )


class Malware(Converter):
    """Represent a Malware Object."""

    name: str = Field(description="Name of the attack pattern.", min_length=1)
    aliases: Optional[str] = Field(
        default=None,
        description="Aliases of the attack pattern.",
    )
    is_family: Optional[bool] = Field(
        default=False,
        description="Indicates whether the malware is a family (True) or a specific instance/sample (False).",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of the attack pattern.",
    )
    author: Optional[Author] = Field(
        description="Author of the attack pattern.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        default=None,
        description="Markings of the attack pattern.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        default=None,
        description="An external link to the parent security incident data.",
    )

    def to_stix2_object(self) -> stix2.Malware:
        """Make stix object."""
        return stix2.Malware(
            id=pycti.Malware.generate_id(name=self.name),
            created_by_ref=self.author.id,
            name=self.name,
            aliases=self.aliases,
            description=self.description,
            is_family=self.is_family,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_external_references": [
                    external_references.to_stix2_object()
                    for external_references in self.external_references or []
                ],
            },
        )


class Tool(Converter):
    """Represent a Tool Object."""

    name: str = Field(description="Name of the attack pattern.", min_length=1)
    aliases: Optional[str] = Field(
        default=None,
        description="Aliases of the attack pattern.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of the attack pattern.",
    )
    author: Optional[Author] = Field(
        description="Author of the attack pattern.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        default=None,
        description="Markings of the attack pattern.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        default=None,
        description="An external link to the parent security incident data.",
    )

    def to_stix2_object(self) -> stix2.Tool:
        """Make stix object."""
        return stix2.Tool(
            id=pycti.Tool.generate_id(name=self.name),
            created_by_ref=self.author.id,
            name=self.name,
            aliases=self.aliases,
            description=self.description,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_external_references": [
                    external_references.to_stix2_object()
                    for external_references in self.external_references or []
                ],
            },
        )


class CustomCaseIncident(Converter):
    """Represent a Custom Object Case Incident."""

    name: str = Field(
        description="The name of the Case Incident is concatenated with the number and a short description",
    )
    description: Optional[str] = Field(
        default=None,
        description="A description of the Case Incident.",
    )
    severity: Optional[str] = Field(
        default=None,
        description="Severity of the Case Incident.",
    )
    # Information: priority is an OpenCTi openvocable whose default value is (P1,P2,P3,P4) but is not mandatory.
    priority: Optional[str] = Field(
        default=None,
        description="Priority of the Case Incident.",
    )
    # Warning: the response_types requires the name on the platform OpenCTI to already exist.
    # It will be filtered by the platform otherwise.
    types: Optional[str] = Field(
        default=None,
        description="Type of the Case Incident.",
    )
    author: Optional[Author] = Field(
        default=None,
        description="Author of the case incident.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        default=None,
        description="Markings of the case incident.",
    )
    objects: Optional[list[Converter]] = Field(
        default=None,
        description="A list of objects associated with the case incident.",
    )
    labels: Optional[list[str]] = Field(
        default=None,
        description="A Labels of the case incident.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        default=None,
        description="External references of the case incident.",
    )
    created: datetime = Field(
        description="The creation date of the case incident.",
    )
    updated: Optional[datetime] = Field(
        default=None,
        description="The update date of the case incident.",
    )

    def to_stix2_object(self) -> pycti.CustomObjectCaseIncident:
        """Make stix object."""
        return pycti.CustomObjectCaseIncident(
            id=pycti.CaseIncident.generate_id(name=self.name, created=self.created),
            name=self.name,
            description=self.description,
            severity=self.severity,
            priority=self.priority,
            response_types=[self.types],
            object_marking_refs=[marking.id for marking in self.markings or []],
            object_refs=[obj.id for obj in self.objects or []],
            created=self.created,
            modified=self.updated,
            custom_properties={
                "x_opencti_labels": self.labels or [],
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_external_references": [
                    external_references.to_stix2_object()
                    for external_references in self.external_references or []
                ],
            },
        )


class CustomTask(Converter):
    """Represent a Custom Object Task."""

    name: str = Field(
        description="The name of the task is concatenated with the number and a short description",
    )
    description: str = Field(
        description="A description of the task.",
    )
    created: datetime = Field(
        description="The creation date of the task.",
    )
    updated: Optional[datetime] = Field(
        default=None,
        description="The update date of the task.",
    )
    due_date: Optional[datetime] = Field(
        default=None,
        description="The due date of the task, representing the deadline for completion.",
    )
    objects: Optional[list[Converter]] = Field(
        default=None,
        description="A list of objects associated with the task.",
    )
    markings: list[TLPMarking] = Field(
        description="Traffic Light Protocol (TLP) markings associated with the task to indicate the sensitivity of the information.",
    )
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the task.",
    )
    author: Author = Field(
        description="Author of the task.",
    )

    def to_stix2_object(self) -> pycti.CustomObjectTask:
        """Converted to Stix 2.1 object."""
        return pycti.CustomObjectTask(
            id=pycti.Task.generate_id(self.name, self.created),
            name=self.name,
            description=self.description,
            created=self.created,
            modified=self.updated,
            due_date=self.due_date,
            object_refs=[obj.id for obj in self.objects or []],
            object_marking_refs=[marking.id for marking in self.markings or []],
            labels=self.labels or [],
            custom_properties={"x_opencti_created_by_ref": self.author.id},
        )


class Relationship(Converter):
    """Represent a Base relationship."""

    author: Author = Field(
        description="Reference to the author that reported this relationship."
    )
    original_creation_date: Optional[datetime] = Field(
        default=None,
        description="This optional datetime represents the original creation date, the date on which the relationship "
        "began to be relevant or observed.",
    )
    modification_date: Optional[datetime] = Field(
        default=None,
        description="This optional datetime represents the modification date, the date on which the relationship "
        "was updated.",
    )
    relationship_type: str = Field(description="Reference to the type of relationship.")
    source: Converter = Field(
        description="Reference to the source entity of the relationship."
    )
    target: Converter = Field(
        description="Reference to the target entity of the relationship."
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")

    def to_stix2_object(self) -> stix2.Relationship:
        """Converted to Stix 2.1 object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                self.relationship_type, self.source.id, self.target.id
            ),
            created=self.original_creation_date,
            modified=self.modification_date,
            relationship_type=self.relationship_type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            object_marking_refs=[marking.id for marking in self.markings or []],
            created_by_ref=self.author.id,
        )


class DomainName(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a domain name.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.DomainName:
        """Converted to Stix 2.1 object."""
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class IPv4Address(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Ipv4 Address or Network.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.IPv4Address:
        """Converted to Stix 2.1 object."""
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class IPv6Address(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Ipv6 Address or Network.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.IPv6Address:
        """Converted to Stix 2.1 object."""
        return stix2.IPv6Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class URL(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a url.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.URL:
        """Converted to Stix 2.1 object."""
        return stix2.URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class EmailAddress(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Email Address.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.EmailAddress:
        """Converted to Stix 2.1 object."""
        return stix2.EmailAddress(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class EmailMessage(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Email Message ID or Body or Subject.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.EmailMessage:
        """Converted to Stix 2.1 object."""
        # field_name available: "Body", "Message_id", "Subject"
        observable_type, field_name = self.type.split("--", maxsplit=1)
        new_field = {field_name.lower(): self.value}
        if field_name == "Message_id":
            new_field["subject"] = self.value

        return stix2.EmailMessage(
            **new_field,
            is_multipart=False,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": observable_type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            }
        )


class File(Converter):
    name: str = Field(
        description="The name of the observable corresponds to a File.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.File:
        """Converted to Stix 2.1 object."""
        hashes = None
        if self.type in ["MD5", "SHA-1", "SHA-256", "SHA-512"]:
            hashes = {self.type: self.name}
        return stix2.File(
            name=self.name,
            hashes=hashes,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class Directory(Converter):
    path: str = Field(
        description="The path of the observable corresponds to a Directory.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.Directory:
        """Converted to Stix 2.1 object."""
        return stix2.Directory(
            path=self.path,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class Hostname(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Hostname.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> pycti.CustomObservableHostname:
        """Converted to Stix 2.1 object."""
        return pycti.CustomObservableHostname(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class Mutex(Converter):
    name: str = Field(
        description="The name of the observable corresponds to a Mutex.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.Mutex:
        """Converted to Stix 2.1 object."""
        return stix2.Mutex(
            name=self.name,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class ASN(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a ASN.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.AutonomousSystem:
        """Converted to Stix 2.1 object."""
        as_number = asn_regex.match(self.value).group(1)
        return stix2.AutonomousSystem(
            name=self.value,
            number=int(as_number),
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class PhoneNumber(Converter):
    value: str = Field(
        description="The value of the observable corresponds to a Phone number.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> pycti.CustomObservablePhoneNumber:
        """Converted to Stix 2.1 object."""
        return pycti.CustomObservablePhoneNumber(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class WindowsRegistyKey(Converter):
    key: str = Field(
        description="The key of the observable corresponds to a Windows Registry Key.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.WindowsRegistryKey:
        """Converted to Stix 2.1 object."""
        return stix2.WindowsRegistryKey(
            key=self.key,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class UserAccount(Converter):
    user: str = Field(
        description="The user id of the observable corresponds to a UserAccount.",
    )
    type: str = Field(description="The type of observable for OpenCTI.")
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the observables.",
    )
    description: Optional[str] = Field(
        default=None,
        description="A note of the observable.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the observable's data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this observable."
    )
    score: Optional[PositiveInt] = Field(
        default=None, description="References for object marking."
    )
    promote_observable_as_indicator: bool = Field(
        description="Boolean to promote observables into indicators.",
    )

    def to_stix2_object(self) -> stix2.UserAccount:
        """Converted to Stix 2.1 object."""
        return stix2.UserAccount(
            user_id=self.user,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
                "x_opencti_main_observable_type": self.type,
                "x_opencti_score": self.score,
                "x_opencti_create_indicator": self.promote_observable_as_indicator,
            },
        )


class OrganizationName(Converter):
    """Represent an organization."""

    name: str = Field(
        description="Reference to the name of the organization.",
    )
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the organisation.",
    )
    description: Optional[str] = Field(
        description="A note of the organisation.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the organisation data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this organisation."
    )

    def to_stix2_object(self) -> stix2.Identity:
        """Converted to Stix 2.1 object."""
        return stix2.Identity(
            id=pycti.Identity.generate_id(identity_class="unknown", name=self.name),
            name=self.name,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels,
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
            },
        )


class Vulnerability(Converter):
    """Represent a Vulnerability. ("CVE Name" observable in ServiceNow)"""

    name: str = Field(
        description="Reference to the name of the Vulnerability.",
    )
    labels: Optional[list[str]] = Field(
        default=None,
        description="A list of Labels of the Vulnerability.",
    )
    description: Optional[str] = Field(
        default=None,
        description="A note of the Vulnerability.",
    )
    external_reference: Optional[ExternalReference] = Field(
        default=None,
        description="An external link to the Vulnerability data.",
    )
    markings: list[TLPMarking] = Field(description="References for object marking.")
    author: Author = Field(
        description="Reference to the author that reported this Vulnerability."
    )

    def to_stix2_object(self) -> stix2.Vulnerability:
        """Converted to Stix 2.1 object."""
        return stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(name=self.name),
            name=self.name,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
                "x_opencti_labels": self.labels or [],
                "x_opencti_description": self.description,
                "x_opencti_external_references": (
                    [self.external_reference.to_stix2_object()]
                    if self.external_reference
                    else []
                ),
            },
        )
