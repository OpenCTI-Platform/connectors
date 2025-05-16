"""The module defines the IntrusionSetModel class, which represents a STIX 2.1 Intrusion Set object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.stix.v21.models.ovs.attack_resource_level_ov_enums import (
    AttackResourceLevelOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import IntrusionSet, _STIXBase21  # type: ignore


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

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return IntrusionSet(**self.model_dump(exclude_none=True))


def test_intrusion_set_model() -> None:
    """Test function to demonstrate the usage of IntrusionSetModel."""
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    # === Minimal Intrusion Set ===
    minimal = IntrusionSetModel(
        type="intrusion-set",
        spec_version="2.1",
        id=f"intrusion-set--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        name="APT-Zero",
    )

    print("=== MINIMAL INTRUSION SET ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Intrusion Set ===
    now = datetime.now(UTC)
    full = IntrusionSetModel(
        type="intrusion-set",
        spec_version="2.1",
        id=f"intrusion-set--{uuid4()}",
        created=now,
        modified=now,
        name="Black Hydra Division",
        description="A persistent state-sponsored intrusion set with ties to eastern bloc cyber ops.",
        aliases=["Hydra Set", "APT-BHD", "Group 77"],
        first_seen=now - timedelta(days=730),
        last_seen=now - timedelta(days=30),
        goals=[
            "Compromise critical infrastructure",
            "Exfiltrate R&D data",
            "Disrupt communications",
        ],
        resource_level=AttackResourceLevelOV.GOVERNMENT,
        primary_motivation=AttackMotivationOV.IDEOLOGY,
        secondary_motivations=[
            AttackMotivationOV.DOMINANCE,
        ],
        labels=["apt", "state-sponsored", "high-threat"],
        confidence=95,
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
                "classification_level": "top-secret",
            }
        },
    )

    print("\n=== FULL INTRUSION SET ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_intrusion_set_model()
