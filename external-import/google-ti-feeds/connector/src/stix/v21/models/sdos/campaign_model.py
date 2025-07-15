"""The module contains the CampaignModel class, which represents a STIX 2.1 Campaign object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Campaign,
    _STIXBase21,
)


class CampaignModel(BaseSDOModel):
    """Model representing a Campaign in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify the Campaign.")
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Campaign.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="The time that this Campaign was first seen. May be updated if earlier sightings are received.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="The time that this Campaign was last seen. Must be >= first_seen. May be updated with newer sighting data.",
    )
    objective: Optional[str] = Field(
        default=None,
        description="Defines the Campaign’s primary goal, objective, desired outcome, or intended effect — what the Threat Actor or Intrusion Set hopes to accomplish.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = CampaignModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            data["id"] = pycti.Campaign.generate_id(name=data["name"])
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = CampaignModel._generate_id(data=data)
        data.pop("id")

        return Campaign(id=pycti_id, **data)
