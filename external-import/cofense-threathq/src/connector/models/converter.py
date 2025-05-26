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