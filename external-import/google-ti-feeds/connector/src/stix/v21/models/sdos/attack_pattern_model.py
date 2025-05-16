"""The module contains the AttackPatternModel class, which represents an attack pattern in STIX 2.1 format."""

from typing import List, Optional

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import AttackPattern, _STIXBase21  # type: ignore


class AttackPatternModel(BaseSDOModel):
    """Model representing an Attack Pattern in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify the Attack Pattern.")
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Attack Pattern.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="The list of Kill Chain Phases for which this Attack Pattern is used.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return AttackPattern(**self.model_dump(exclude_none=True))


def test() -> None:
    """Test function to demonstrate the usage of AttackPatternModel."""
    from datetime import datetime
    from uuid import uuid4

    from connector.src.stix.v21.models.cdts.external_reference_model import (
        ExternalReferenceModel,
    )

    # === Required Only ===
    required_only = AttackPatternModel(
        type="attack-pattern",
        spec_version="2.1",
        id=f"attack-pattern--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Required Attack Pattern",
    )

    print("=== REQUIRED ONLY ===")  # noqa: T201
    print(required_only.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Fully Populated ===
    full_attack_pattern = AttackPatternModel(
        type="attack-pattern",
        spec_version="2.1",
        id=f"attack-pattern--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Full Spectrum Exploit",
        description="A complex, multi-phase exploitation of vulnerable firmware.",
        aliases=["Spectre 2.0", "Firmware Ghost"],
        labels=["exploit", "firmware", "advanced"],
        confidence=90,
        lang="en",
        created_by_ref=f"identity--{uuid4()}",
        revoked=False,
        external_references=[
            ExternalReferenceModel(
                source_name="capec",
                external_id="CAPEC-137",
                url="https://capec.mitre.org/data/definitions/137.html",
                description="Example CAPEC technique for firmware exploitation",
            )
        ],
        kill_chain_phases=[
            KillChainPhaseModel(kill_chain_name="mitre-attack", phase_name="execution"),
            KillChainPhaseModel(
                kill_chain_name="mitre-attack", phase_name="persistence"
            ),
        ],
        object_marking_refs=[
            f"marking-definition--{uuid4()}",
        ],
        granular_markings=[
            {
                "selectors": ["name"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "custom_field": "value",
            }
        },
    )

    print("\n=== FULL ATTACK PATTERN ===")  # noqa: T201
    print(  # noqa: T201
        full_attack_pattern.to_stix2_object().serialize(pretty=True)
    )  # noqa: T201


if __name__ == "__main__":
    test()
