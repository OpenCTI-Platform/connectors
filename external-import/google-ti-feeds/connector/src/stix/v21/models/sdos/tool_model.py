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
