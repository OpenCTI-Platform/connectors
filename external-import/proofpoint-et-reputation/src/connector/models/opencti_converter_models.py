from abc import abstractmethod
from ipaddress import IPv4Address
from typing import Any, Literal, Optional

import pycti
import stix2
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


class OCTIConverter(BaseModel):
    """
    Base class for OpenCTI models.
    OpenCTI models are extended implementations of STIX 2.1 specification.
    All OpenCTI models implement `to_stix2_object` method to return a validated and formatted STIX 2.1 dict.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

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
        self._id = self._stix2_representation["id"]

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


class Author(OCTIConverter):
    """Represent an author identity, typically an organization."""

    name: str = Field(..., description="Reference to the name of the author.")
    identity_class: str = Field(
        ..., description="Reference to the identity class of the author (organization)."
    )
    description: str = Field(
        ..., description="Reference to the description of the author."
    )
    x_opencti_organization_type: Optional[
        Literal["vendor", "partner", "constituent", "csirt", "other"]
    ] = Field(None, description="Reference to Open CTI Type of the author.")

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
                "x_opencti_organization_type": self.x_opencti_organization_type
            },
        )


class MarkingDefinition(OCTIConverter):
    """Represent a Marking definition."""

    definition_type: str = Field(
        ...,
        description="Reference to the value of the definition_type property MUST be statement when using this marking type.",
    )
    definition: dict = Field(
        ...,
        description="Reference to the definition property contains the marking object itself (TLP).",
    )
    x_opencti_definition_type: str = Field(
        ..., description="Reference to custom OpenCTI marking type (TLP)."
    )
    x_opencti_definition: str = Field(
        ...,
        description="Reference to custom OpenCTI marking definition. (TLP:AMBER+STRICT).",
    )

    def to_stix2_object(self) -> stix2.MarkingDefinition:
        """Converted to Stix 2.1 object."""
        return stix2.MarkingDefinition(
            id=pycti.MarkingDefinition.generate_id(
                self.x_opencti_definition_type, self.x_opencti_definition
            ),
            definition_type=self.definition_type,
            definition=self.definition,
            custom_properties={
                "x_opencti_definition_type": self.x_opencti_definition_type,
                "x_opencti_definition": self.x_opencti_definition,
            },
        )


class Relationship(OCTIConverter):
    """Represent a Base relationship."""

    created_by: Author = Field(
        ..., description="Reference to the author that reported this relationship."
    )
    relationship_type: str = Field(
        ..., description="Reference to the type of relationship."
    )
    source: OCTIConverter = Field(
        ..., description="Reference to the source entity of the relationship."
    )
    target: OCTIConverter = Field(
        ..., description="Reference to the target entity of the relationship."
    )
    markings: list[MarkingDefinition] = Field(
        ..., description="References for object marking, TLP:AMBER+STRICT by default."
    )

    def to_stix2_object(self) -> stix2.Relationship:
        """Converted to Stix 2.1 object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                self.relationship_type, self.source.id, self.target.id
            ),
            relationship_type=self.relationship_type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            object_marking_refs=[marking.id for marking in self.markings],
            created_by_ref=self.created_by.id,
        )


class Observable(OCTIConverter):
    """Represent observables associated with a system or an asset."""

    value: IPv4Address | str = Field(
        ..., description="Reference to the IPv4 or DomainName value."
    )
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of object marking TLP:AMBER+STRICT."
    )
    x_opencti_score: int = Field(
        ..., description="Reference to the score for the observable."
    )
    x_opencti_labels: list[str] = Field(
        ..., description="Reference to labels associated with the observable."
    )
    x_opencti_created_by: Author = Field(
        ..., description="Reference to the author that reported the observable."
    )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """
        Abstract method to construct the corresponding STIX 2.1 object
        (usually from stix2 python lib objects)
        """


class IPAddress(Observable):
    """Represent a ipv4 observable."""

    def to_stix2_object(self) -> stix2.IPv4Address:
        """Converted to Stix 2.1 object."""
        return stix2.IPv4Address(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_score": self.x_opencti_score,
                "x_opencti_labels": self.x_opencti_labels,
                "x_opencti_created_by_ref": self.x_opencti_created_by.id,
            },
        )


class DomainName(Observable):
    """Represent a domain name observable."""

    def to_stix2_object(self) -> stix2.DomainName:
        """Converted to Stix 2.1 object."""
        return stix2.DomainName(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_score": self.x_opencti_score,
                "x_opencti_labels": self.x_opencti_labels,
                "x_opencti_created_by_ref": self.x_opencti_created_by.id,
            },
        )


class Indicator(OCTIConverter):
    """Represent an Indicator."""

    name: IPv4Address | str = Field(
        ..., description="Reference to the name of the indicator."
    )
    pattern: str = Field(
        ..., description="Reference to the STIX pattern that represents the indicator."
    )
    pattern_type: str = Field(
        ..., description="Reference to the type of the STIX pattern (stix)."
    )
    markings: list[MarkingDefinition] = Field(
        ..., description="Reference to list of marking definitions for the indicator."
    )
    created_by: Author = Field(
        ..., description="Reference to the author of the indicator."
    )
    labels: list[str] = Field(
        ..., description="Reference to labels associated with the indicator"
    )
    x_opencti_score: int = Field(
        ..., description="Reference to the score for the indicator"
    )
    x_opencti_main_observable_type: str = Field(
        ...,
        description="Reference to the main observable type associated with the indicator",
    )

    def to_stix2_object(self) -> stix2.Indicator:
        """Converted to Stix 2.1 object."""
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self.pattern),
            created_by_ref=self.created_by.id,
            name=self.name,
            pattern=self.pattern,
            pattern_type=self.pattern_type,
            labels=self.labels,
            object_marking_refs=[marking.id for marking in self.markings],
            custom_properties={
                "x_opencti_score": self.x_opencti_score,
                "x_opencti_main_observable_type": self.x_opencti_main_observable_type,
            },
        )
