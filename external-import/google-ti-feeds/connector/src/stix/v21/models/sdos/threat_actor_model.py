"""The module defines a Threat Actor model for STIX 2.1, including validation and serialization methods."""

from datetime import datetime
from typing import List, Optional

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
from stix2.v21 import ThreatActor, _STIXBase21  # type: ignore


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
        if (
            self.first_seen
            and self.last_seen
            and self.last_seen < self.first_seen
        ):
            raise ValueError(
                "'last_seen' must be greater than or equal to 'first_seen'."
            )
        return self

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return ThreatActor(**self.model_dump(exclude_none=True))


def test_threat_actor_model() -> None:
    """Test function to demonstrate the usage of ThreatActorModel."""
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Threat Actor ===
    minimal = ThreatActorModel(
        type="threat-actor",
        spec_version="2.1",
        id=f"threat-actor--{uuid4()}",
        created=now,
        modified=now,
        name="APT Ghost",
        threat_actor_types=[ThreatActorTypeOV.ACTIVIST],
    )

    print("=== MINIMAL THREAT ACTOR ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Threat Actor ===
    full = ThreatActorModel(
        type="threat-actor",
        spec_version="2.1",
        id=f"threat-actor--{uuid4()}",
        created=now,
        modified=now,
        name="Hydra Vanguard",
        description="An elite unit suspected of developing advanced cross-platform espionage tools for state operations.",
        threat_actor_types=[
            ThreatActorTypeOV.NATION_STATE,
            ThreatActorTypeOV.SPY,
        ],
        aliases=["Shadow Hydra", "Ghost Regiment", "APT-HYDRA"],
        first_seen=now - timedelta(days=820),
        last_seen=now - timedelta(days=2),
        roles=[
            ThreatActorRoleOV.MALWARE_AUTHOR,
            ThreatActorRoleOV.INDEPENDENT,
        ],
        goals=[
            "Surveillance of military infrastructure",
            "Credential harvesting",
            "Disruption of satellite uplinks",
        ],
        sophistication=ThreatActorSophisticationOV.INNOVATOR,
        resource_level=AttackResourceLevelOV.GOVERNMENT,
        primary_motivation=AttackMotivationOV.DOMINANCE,
        secondary_motivations=[
            AttackMotivationOV.IDEOLOGY,
            AttackMotivationOV.DOMINANCE,
        ],
        personal_motivations=[AttackMotivationOV.PERSONAL_SATISFACTION],
        labels=["apt", "espionage", "high-skill"],
        confidence=93,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description", "goals"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "classification": "tier-1 threat",
            }
        },
    )

    print("\n=== FULL THREAT ACTOR ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_threat_actor_model()
