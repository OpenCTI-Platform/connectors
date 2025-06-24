"""The module defines a Threat Actor model for STIX 2.1, including validation and serialization methods."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.stix.v21.models.ovs.attack_resource_level_ov_enums import (
    AttackResourceLevelOV,
)
from connector.src.stix.v21.models.ovs.threat_actor_role_ov_enums import (
    ThreatActorRoleOV,
)
from connector.src.stix.v21.models.ovs.threat_actor_sophistication_ov_enums import (
    ThreatActorSophisticationOV,
)
from connector.src.stix.v21.models.ovs.threat_actor_type_ov_enums import (
    ThreatActorTypeOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    ThreatActor,
    _STIXBase21,
)


class ThreatActorModel(BaseSDOModel):
    """Model representing a Threat Actor in STIX 2.1 format."""

    name: str = Field(
        ..., description="A name used to identify this Threat Actor or group."
    )
    description: Optional[str] = Field(
        default=None,
        description="Context and characteristics of the Threat Actor—who they are, how they operate, and why.",
    )

    threat_actor_types: List[ThreatActorTypeOV] = Field(
        ...,
        description="Open vocab describing the type(s) of this Threat Actor. SHOULD come from threat-actor-type-ov.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Other names believed to refer to the same Threat Actor.",
    )

    first_seen: Optional[datetime] = Field(
        default=None,
        description="Time this Threat Actor was first seen. May be updated with earlier sightings.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Time this Threat Actor was last seen. MUST be >= first_seen if both are set.",
    )

    roles: Optional[List[ThreatActorRoleOV]] = Field(
        default=None,
        description="Roles this Threat Actor plays. SHOULD come from threat-actor-role-ov.",
    )
    goals: Optional[List[str]] = Field(
        default=None,
        description="High-level goals of the Threat Actor (e.g., steal credit card numbers, exfiltrate data).",
    )

    sophistication: Optional[ThreatActorSophisticationOV] = Field(
        default=None,
        description="Level of knowledge, training, or expertise. SHOULD come from threat-actor-sophistication-ov.",
    )
    resource_level: Optional[AttackResourceLevelOV] = Field(
        default=None,
        description="Organizational level this Threat Actor operates at. SHOULD come from attack-resource-level-ov.",
    )

    primary_motivation: Optional[AttackMotivationOV] = Field(
        default=None,
        description="Primary reason driving this Threat Actor. SHOULD come from attack-motivation-ov.",
    )
    secondary_motivations: Optional[List[AttackMotivationOV]] = Field(
        default=None,
        description="Additional motivations influencing this Threat Actor. SHOULD come from attack-motivation-ov.",
    )
    personal_motivations: Optional[List[AttackMotivationOV]] = Field(
        default=None,
        description="Personal (non-organizational) motivations behind actions. SHOULD come from attack-motivation-ov.",
    )

    @model_validator(mode="after")
    def validate_seen_window(self) -> "ThreatActorModel":
        """Ensure 'last_seen' is greater than or equal to 'first_seen'."""
        if self.first_seen and self.last_seen and self.last_seen < self.first_seen:
            raise ValueError(
                "'last_seen' must be greater than or equal to 'first_seen'."
            )
        return self

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = ThreatActorModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            name = data.get("name", None)
            opencti_type = data.get("custom_properties", {}).get("opencti_type", None)
            data["id"] = pycti.ThreatActor.generate_id(
                name=name, opencti_type=opencti_type
            )
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = ThreatActorModel._generate_id(data=data)
        data.pop("id")

        return ThreatActor(id=pycti_id, **data)
