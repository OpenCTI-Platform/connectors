"""The module defines the BaseSCOModel class, which serves as a base model for all STIX Cyber Observable (SCO) objects."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    _STIXBase21,
)


class SCORequiredModel(BaseModel):
    """Required fields for all STIX Cyber Observable (SCO) objects."""

    type: str = Field(
        ...,
        description="The object type. MUST match the specific SCO type being defined.",
    )
    id: str = Field(description="The unique STIX identifier for this SCO object.")


class SCOOptionalModel(BaseModel):
    """Optional fields for all STIX Cyber Observable (SCO) objects."""

    spec_version: Optional[str] = Field(
        default=None,
        description="The STIX specification version, typically '2.1'.",
    )
    object_marking_refs: Optional[List[str]] = Field(
        default=None,
        description="List of marking-definition IDs applied to this object.",
    )
    granular_markings: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of granular markings on specific fields.",
    )
    defanged: Optional[bool] = Field(
        default=None,
        description="Whether the object has been defanged to prevent accidental execution.",
    )
    extensions: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom STIX extensions applied to this object.",
    )
    custom_properties: Optional[dict[str, Any]] = Field(
        default=None,
        description="Custom properties that are not part of the STIX specification.",
    )


class BaseSCOModel(SCORequiredModel, SCOOptionalModel):
    """Base class for all STIX Cyber Observable (SCO) objects."""

    def to_stix2_object(self) -> _STIXBase21:
        """Convert to a STIX 2.1 object."""
        raise NotImplementedError("Subclasses must implement this method.")
