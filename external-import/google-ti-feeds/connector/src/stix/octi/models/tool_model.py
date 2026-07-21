"""The module contains the OctiToolModel class, which represents an OpenCTI Tool."""

from datetime import datetime
from typing import Any

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.tool_type_ov_enums import ToolTypeOV
from connector.src.stix.v21.models.sdos.tool_model import ToolModel


class OctiToolModel:
    """Model for creating OpenCTI Tool objects."""

    @staticmethod
    def create(
        name: str,
        organization_id: str,
        marking_ids: list[str],
        tool_types: list[ToolTypeOV],
        description: str | None = None,
        aliases: list[str] | None = None,
        kill_chain_phases: list[KillChainPhaseModel] | None = None,
        tool_version: str | None = None,
        **kwargs: Any,
    ) -> ToolModel:
        """Create a Tool model.

        Args:
            name: The name of the tool
            organization_id: The ID of the organization that created this tool
            marking_ids: list of marking definition IDs to apply to the tool
            tool_types: list of tool types from tool-type-ov
            description: Description of the tool
            aliases: Alternative names for the tool
            kill_chain_phases: Kill chain phases associated with the tool
            tool_version: Version identifier of the tool
            **kwargs: Additional arguments to pass to ToolModel

        Returns:
            ToolModel: The created tool model

        """
        data = {
            "type": "tool",
            "spec_version": "2.1",
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "tool_types": tool_types,
            "aliases": aliases,
            "kill_chain_phases": kill_chain_phases,
            "tool_version": tool_version,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return ToolModel(**data)
