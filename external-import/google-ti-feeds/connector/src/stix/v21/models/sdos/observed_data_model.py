"""The module defines the ObservedDataModel class, which represents a STIX 2.1 Observed Data object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    ObservedData,
    _STIXBase21,
)


class ObservedDataModel(BaseSDOModel):
    """Model representing an Observed Data in STIX 2.1 format."""

    first_observed: datetime = Field(
        ..., description="Start time of the observation window."
    )
    last_observed: datetime = Field(
        ...,
        description="End time of the observation window. MUST be >= first_observed.",
    )
    number_observed: int = Field(
        ...,
        ge=1,
        le=999_999_999,
        description="Number of times the data was observed. MUST be an integer between 1 and 999,999,999 inclusive.",
    )
    objects: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="(Deprecated) Dictionary of SCOs observed. MUST NOT be present if object_refs is set. Will be removed in future STIX versions.",
    )
    object_refs: Optional[List[str]] = Field(
        default=None,
        description="List of references to SCOs/SROs observed. MUST NOT be set if 'objects' is present.",
    )

    @model_validator(mode="after")
    def validate_observed_data(self) -> "ObservedDataModel":
        """Validate the ObservedDataModel instance."""
        if self.last_observed < self.first_observed:
            raise ValueError(
                "'last_observed' must be greater than or equal to 'first_observed'."
            )
        if self.objects and self.object_refs:
            raise ValueError(
                "Only one of 'objects' or 'object_refs' may be set—not both."
            )
        if not self.objects and not self.object_refs:
            raise ValueError("At least one of 'objects' or 'object_refs' must be set.")
        return self

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = ObservedDataModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "object_refs" in data:
            object_ids = data.get("object_refs", [])
            data["id"] = pycti.ObservedData.generate_id(object_ids=object_ids)
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = ObservedDataModel._generate_id(data=data)
        data.pop("id")

        return ObservedData(id=pycti_id, **data)
