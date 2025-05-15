"""The module defines the InfrastructureModel class, which represents a STIX 2.1 Infrastructure object."""

from datetime import datetime
from typing import List, Optional

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.infrastructure_type_ov_enums import (
    InfrastructureTypeOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Infrastructure, _STIXBase21  # type: ignore


class InfrastructureModel(BaseSDOModel):
    """Model representing an Infrastructure in STIX 2.1 format."""

    name: str = Field(
        ...,
        description="A name or characterizing text used to identify the Infrastructure.",
    )
    description: Optional[str] = Field(
        default=None,
        description="More details and context about the Infrastructure—purpose, use, relationships, and key characteristics.",
    )
    infrastructure_types: List[InfrastructureTypeOV] = Field(
        ...,
        description="Open vocabulary describing the type(s) of Infrastructure. SHOULD come from the infrastructure-type-ov vocabulary.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Infrastructure.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="Kill Chain Phases for which this Infrastructure is used.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Infrastructure was first observed performing malicious activity.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Infrastructure was last observed. MUST be >= first_seen if both are present.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Infrastructure(**self.model_dump(exclude_none=True))


def test_infrastructure_model() -> None:
    """Test function to demonstrate the usage of InfrastructureModel."""
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    # === Minimal Infrastructure ===
    minimal = InfrastructureModel(
        type="infrastructure",
        spec_version="2.1",
        id=f"infrastructure--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        name="C2 Gateway A",
        infrastructure_types=[InfrastructureTypeOV.COMMAND_AND_CONTROL],
    )

    print("=== MINIMAL INFRASTRUCTURE ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Infrastructure ===
    now = datetime.now(UTC)
    full = InfrastructureModel(
        type="infrastructure",
        spec_version="2.1",
        id=f"infrastructure--{uuid4()}",
        created=now,
        modified=now,
        name="Hydra VPN Relay Cluster",
        description="A rotating cluster of anonymized VPN endpoints used for lateral movement and data exfiltration.",
        infrastructure_types=[InfrastructureTypeOV.ANONYMIZATION],
        aliases=["HydraRelay", "GhostTunnel"],
        kill_chain_phases=[
            KillChainPhaseModel(
                kill_chain_name="mitre-attack", phase_name="lateral-movement"
            ),
            KillChainPhaseModel(
                kill_chain_name="mitre-attack", phase_name="exfiltration"
            ),
        ],
        first_seen=now - timedelta(days=90),
        last_seen=now - timedelta(days=5),
        labels=["infrastructure", "vpn", "stealth"],
        confidence=80,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description", "name"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "suspicion_score": 8.3,
            }
        },
    )

    print("\n=== FULL INFRASTRUCTURE ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_infrastructure_model()
