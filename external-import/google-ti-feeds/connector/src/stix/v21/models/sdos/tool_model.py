"""The module defines the ToolModel class, which represents a STIX 2.1 Tool object."""

from typing import List, Optional

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.tool_type_ov_enums import ToolTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Tool, _STIXBase21  # type: ignore


class ToolModel(BaseSDOModel):
    """Model representing a Tool in STIX 2.1 format."""

    name: str = Field(..., description="The name used to identify the Tool.")
    description: Optional[str] = Field(
        default=None,
        description="Details about the Tool's purpose, use, and characteristics.",
    )
    tool_types: List[ToolTypeOV] = Field(
        ...,
        description="Open vocabulary of tool types. SHOULD come from tool-type-ov.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Tool.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="Kill Chain Phases where this Tool can be used.",
    )
    tool_version: Optional[str] = Field(
        default=None, description="Version identifier of the Tool."
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Tool(**self.model_dump(exclude_none=True))


def test_tool_model() -> None:
    """Test function to demonstrate the usage of ToolModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Tool ===
    minimal = ToolModel(
        type="tool",
        spec_version="2.1",
        id=f"tool--{uuid4()}",
        created=now,
        modified=now,
        name="PowerDump",
        tool_types=[ToolTypeOV.INFORMATION_GATHERING],
    )

    print("=== MINIMAL TOOL ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Tool ===
    full = ToolModel(
        type="tool",
        spec_version="2.1",
        id=f"tool--{uuid4()}",
        created=now,
        modified=now,
        name="BlackFang RAT",
        description="Remote access tool used to maintain control over compromised endpoints. Features obfuscation and reverse shell capability.",
        tool_types=[ToolTypeOV.REMOTE_ACCESS, ToolTypeOV.EXPLOITATION],
        aliases=["BFRAT", "FangAgent"],
        kill_chain_phases=[
            KillChainPhaseModel(
                kill_chain_name="mitre-attack",
                phase_name="command-and-control",
            ),
            KillChainPhaseModel(
                kill_chain_name="mitre-attack", phase_name="collection"
            ),
        ],
        tool_version="v3.2.7-beta",
        labels=["rat", "stealth", "c2"],
        confidence=88,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description", "tool_version"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "telemetry": "enabled",
            }
        },
    )

    print("\n=== FULL TOOL ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_tool_model()
