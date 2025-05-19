"""The moduleq defines the base model for STIX Domain Objects (SDOs) in STIX 2.1 format."""

from datetime import datetime
from typing import Any, List, Optional

from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from pydantic import BaseModel, Field
from stix2.v21 import _STIXBase21  # type: ignore


class SDORequiredModel(BaseModel):
    """Required fields for all STIX Domain Objects (SDOs)."""

    type: str = Field(..., description="The object type, must match the SDO type.")
    spec_version: str = Field(
        ..., description="The STIX specification version, e.g., '2.1'."
    )
    id: str = Field(..., description="The unique STIX identifier for this object.")
    created: datetime = Field(
        ..., description="Timestamp when this object was created."
    )
    modified: datetime = Field(
        ..., description="Timestamp when this object was last modified."
    )


class SDOOptionalModel(BaseModel):
    """Optional fields for all STIX Domain Objects (SDOs)."""

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
    external_references: Optional[List[ExternalReferenceModel]] = Field(
        default=None,
        description="List of external references relevant to this object.",
    )
    object_marking_refs: Optional[List[str]] = Field(
        default=None,
        description="List of marking-definition IDs that apply to this object.",
    )
    granular_markings: Optional[List[Any]] = Field(
        default=None,
        description="Granular markings on specific object fields.",
    )
    extensions: Optional[dict[str, Any]] = Field(
        default=None,
        description="Custom STIX extensions applied to this object.",
    )
    custom_properties: Optional[dict[str, Any]] = Field(
        default=None,
        description="Custom properties that are not part of the STIX specification.",
    )


class BaseSDOModel(SDORequiredModel, SDOOptionalModel):
    """Base model for all SDOs (STIX Domain Objects)."""

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the Pydantic model to a STIX 2.1 object."""
        raise NotImplementedError("Subclasses must implement this method.")
