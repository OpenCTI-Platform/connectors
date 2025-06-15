"""The module defines the ToolModel class, which represents a STIX 2.1 Tool object."""

from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.tool_type_ov_enums import ToolTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Tool,
    _STIXBase21,
)


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

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = ToolModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            data["id"] = pycti.Tool.generate_id(name=data["name"])
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = ToolModel._generate_id(data=data)
        data.pop("id")

        return Tool(id=pycti_id, **data)
