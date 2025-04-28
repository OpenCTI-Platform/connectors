from abc import abstractmethod
from datetime import datetime
from typing import Any, Literal, Optional

import pycti
import stix2
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


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
            custom_properties={"x_opencti_organization_type": self.organization_type},
            external_references=[
                stix2.ExternalReference(
                    source_name="ServiceNow",
                    url="https://www.servicenow.com/",
                    description="Official site of ServiceNow.",
                )
            ],
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
            description=self.description,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                external_references.to_stix2_object()
                for external_references in self.external_references or []
            ],
            aliases=self.aliases,
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
            description=self.description,
            is_family=self.is_family,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                external_references.to_stix2_object()
                for external_references in self.external_references or []
            ],
            aliases=self.aliases,
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
            description=self.description,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                external_references.to_stix2_object()
                for external_references in self.external_references or []
            ],
            aliases=self.aliases,
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
    labels: Optional[str] = Field(
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
            external_references=[
                external_references.to_stix2_object()
                for external_references in self.external_references or []
            ],
            created=self.created,
            modified=self.updated,
            custom_properties={
                "x_opencti_labels": [self.labels] if self.labels else [],
                "x_opencti_created_by_ref": self.author.id,
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
    objects: Optional[Converter] = Field(
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
            object_refs=[self.objects.id],
            object_marking_refs=[marking.id for marking in self.markings or []],
            labels=self.labels,
            custom_properties={"x_opencti_created_by_ref": self.author.id},
        )


class Relationship(Converter):
    """Represent a Base relationship."""

    author: Author = Field(
        description="Reference to the author that reported this relationship."
    )
    start_time: Optional[datetime] = Field(
        default=None,
        description="This optional timestamp represents the earliest time at which the Relationship between the objects exists.",
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
            start_time=self.start_time,
            relationship_type=self.relationship_type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            object_marking_refs=[marking.id for marking in self.markings],
            created_by_ref=self.author.id,
        )
