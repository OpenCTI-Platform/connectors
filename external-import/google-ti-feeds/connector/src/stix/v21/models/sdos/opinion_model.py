"""The module defines the OpinionModel class, which represents a STIX 2.1 Opinion object."""

from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.opinion_ov_enums import OpinionOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Opinion,
    _STIXBase21,
)


class OpinionModel(BaseSDOModel):
    """Model representing an Opinion in STIX 2.1 format."""

    explanation: Optional[str] = Field(
        default=None,
        description="Explanation for the Opinion, including reasoning and any supporting evidence.",
    )
    authors: Optional[List[str]] = Field(
        default=None,
        description="List of authors (e.g., analysts) who created this Opinion.",
    )
    opinion: OpinionOV = Field(
        ...,
        description="The producer's opinion about the object(s). MUST be a value from the opinion-enum.",
    )
    object_refs: List[str] = Field(
        ...,
        description="STIX Object identifiers that this Opinion applies to.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = OpinionModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "created" in data:
            created = data.get("created", None)
            opinion = data.get("opinion", None)
            data["id"] = pycti.Opinion.generate_id(created=created, opinion=opinion)
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = OpinionModel._generate_id(data=data)
        data.pop("id")

        return Opinion(id=pycti_id, **data)
