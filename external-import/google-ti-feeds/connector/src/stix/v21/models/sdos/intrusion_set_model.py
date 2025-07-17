"""The module defines the IntrusionSetModel class, which represents a STIX 2.1 Intrusion Set object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.stix.v21.models.ovs.attack_resource_level_ov_enums import (
    AttackResourceLevelOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    IntrusionSet,
    _STIXBase21,
)


class IntrusionSetModel(BaseSDOModel):
    """Model representing an Intrusion Set in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify this Intrusion Set.")
    description: Optional[str] = Field(
        default=None,
        description="Details and context about the Intrusion Set, including its purpose and key characteristics.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Intrusion Set.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Intrusion Set was first seen. May be updated with earlier sightings.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Intrusion Set was last seen. MUST be >= first_seen if both are set.",
    )
    goals: Optional[List[str]] = Field(
        default=None,
        description="High-level goals of this Intrusion Set—what they're trying to achieve.",
    )
    resource_level: Optional[AttackResourceLevelOV] = Field(
        default=None,
        description="Organizational level at which this Intrusion Set operates. SHOULD come from the attack-resource-level-ov vocabulary.",
    )
    primary_motivation: Optional[AttackMotivationOV] = Field(
        default=None,
        description="Primary motivation behind this Intrusion Set. SHOULD come from the attack-motivation-ov vocabulary.",
    )
    secondary_motivations: Optional[List[AttackMotivationOV]] = Field(
        default=None,
        description="Secondary motivations behind this Intrusion Set. SHOULD come from the attack-motivation-ov vocabulary.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = IntrusionSetModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            data["id"] = pycti.IntrusionSet.generate_id(name=data["name"])
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = IntrusionSetModel._generate_id(data=data)
        data.pop("id")

        return IntrusionSet(id=pycti_id, **data)
