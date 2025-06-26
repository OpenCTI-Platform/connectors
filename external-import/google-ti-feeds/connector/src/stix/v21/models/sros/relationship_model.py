"""The module defines a RelationshipModel class that represents a STIX 2.1 Relationship object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from pydantic import BaseModel, Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Relationship,
    _STIXBase21,
)


class RelationshipModel(BaseModel):
    """Model representing a Relationship in STIX 2.1 format."""

    type: str = Field(
        "relationship",
        description="The type of this object, which MUST be 'relationship'.",
    )
    spec_version: str = Field(
        "2.1",
        description="The version of the STIX specification used to represent this object.",
    )
    id: Optional[str] = Field(
        default=None, description="The identifier of this object."
    )
    created: datetime = Field(
        ..., description="The time at which this object was created."
    )
    modified: datetime = Field(
        ..., description="The time at which this object was last modified."
    )

    relationship_type: str = Field(
        ...,
        description="The name used to identify the type of relationship, e.g., 'indicates' or 'mitigates'.",
    )
    source_ref: str = Field(
        ...,
        description="The ID of the source (from) object in the relationship.",
    )
    target_ref: str = Field(
        ...,
        description="The ID of the target (to) object in the relationship.",
    )

    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Relationship.",
    )
    start_time: Optional[datetime] = Field(
        default=None,
        description="When the relationship began or was in effect.",
    )
    stop_time: Optional[datetime] = Field(
        default=None,
        description="When the relationship ended or was no longer in effect.",
    )

    created_by_ref: Optional[str] = Field(
        default=None,
        description="Reference to the identity that created the object.",
    )
    revoked: Optional[bool] = Field(
        default=None,
        description="Indicates whether this object has been revoked.",
    )
    labels: Optional[List[str]] = Field(
        default=None, description="User-defined labels for this object."
    )
    confidence: Optional[int] = Field(
        default=None,
        description="Level of confidence in the accuracy of this object (0–100).",
    )
    lang: Optional[str] = Field(
        default=None, description="Language code used for this object."
    )
    external_references: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of external references relevant to this object.",
    )
    object_marking_refs: Optional[List[str]] = Field(
        default=None,
        description="List of marking-definition IDs that apply to this object.",
    )
    granular_markings: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Granular markings on specific object fields.",
    )
    extensions: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Custom STIX extensions applied to this object.",
    )
    custom_properties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom properties that are not part of the STIX specification.",
    )

    model_config = {"extra": "forbid"}

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = RelationshipModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "relationship_type" in data:
            relationship_type = data.get("relationship_type", None)
            source_ref = data.get("source_ref", None)
            target_ref = data.get("target_ref", None)
            start_time = data.get("start_time", None)
            stop_time = data.get("stop_time", None)

            data["id"] = pycti.StixCoreRelationship.generate_id(
                relationship_type=relationship_type,
                source_ref=source_ref,
                target_ref=target_ref,
                start_time=start_time,
                stop_time=stop_time,
            )
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = RelationshipModel._generate_id(data=data)
        data.pop("id")

        return Relationship(id=pycti_id, **data)
