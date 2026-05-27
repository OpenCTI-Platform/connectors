"""Tool entity model."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import ToolType
from connectors_sdk.models.kill_chain_phase import KillChainPhase
from pycti import Tool as PyctiTool
from pydantic import Field
from stix2.v21 import Tool as Stix2Tool


class Tool(BaseIdentifiedEntity):
    """Represent a tool entity.

    STIX2.1 Tool: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html#tool
    """

    name: str = Field(
        description="Name of the tool.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the tool.",
    )
    tool_types: list[ToolType] | None = Field(
        default=None,
        description="Kind of tool(s) being described, values SHOULD come from "
        "the tool-type-ov vocabulary",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Tool.",
    )
    kill_chain_phases: list[KillChainPhase] | None = Field(
        default=None,
        description="List of kill chain phases for which this Tool can be used.",
    )
    tool_version: str | None = Field(
        default=None,
        description="Version identifier associated with the Tool.",
    )

    def to_stix2_object(self) -> Stix2Tool:
        """Make stix object."""
        return Stix2Tool(
            id=PyctiTool.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            tool_types=self.tool_types,
            aliases=self.aliases,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            tool_version=self.tool_version,
            **self._common_stix2_properties(),
        )
