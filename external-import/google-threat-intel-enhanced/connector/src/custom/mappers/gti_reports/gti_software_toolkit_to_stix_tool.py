"""Converts a GTI software toolkit to a STIX Tool object."""

from datetime import datetime, timezone
from typing import Any, List, Optional

from connector.src.custom.models.gti_reports.gti_software_toolkit_model import (
    Capability,
    GTISoftwareToolkitData,
    MalwareRole,
    SoftwareToolkitModel,
)
from connector.src.stix.v21.models.sdos.tool_model import ToolModel
from connector.src.stix.v21.models.ovs.tool_type_ov_enums import ToolTypeOV
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition, Tool  # type: ignore


class GTISoftwareToolkitToSTIXTool(BaseMapper):
    """Converts a GTI software toolkit to a STIX Tool object."""

    def __init__(
        self,
        software_toolkit: GTISoftwareToolkitData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        **kwargs: Any,
    ) -> None:
        """Initialize the GTISoftwareToolkitToSTIXTool object.

        Args:
            software_toolkit (GTISoftwareToolkitData): The GTI software toolkit data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.software_toolkit = software_toolkit
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> Tool:
        """Convert the GTI software toolkit to a STIX Tool object.

        Returns:
            Tool: The STIX Tool object.

        """
        if (
            not hasattr(self.software_toolkit, "attributes")
            or not self.software_toolkit.attributes
        ):
            # Fallback: use the ID as the name if no attributes
            name = self.software_toolkit.id if hasattr(self.software_toolkit, "id") else "Unknown Tool"
            return self._create_minimal_tool(name)

        attributes = self.software_toolkit.attributes

        created = None
        modified = None
        if attributes.creation_date:
            created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        if attributes.last_modification_date:
            modified = datetime.fromtimestamp(
                attributes.last_modification_date, tz=timezone.utc
            )

        aliases = self._extract_aliases(attributes)
        tool_types = self._extract_tool_types(attributes)
        labels = self._extract_labels(attributes)
        capability_labels = self._extract_capabilities(attributes)

        # Merge labels: tags + capabilities
        all_labels = []
        if labels:
            all_labels.extend(labels)
        if capability_labels:
            all_labels.extend(capability_labels)

        tool_model = ToolModel(
            type="tool",
            spec_version="2.1",
            name=attributes.name,
            description=attributes.description,
            tool_types=tool_types,
            aliases=aliases,
            labels=all_labels if all_labels else None,
            created=created,
            modified=modified,
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )

        return tool_model.to_stix2_object()

    def _create_minimal_tool(self, name: str) -> Tool:
        """Create a minimal STIX Tool with just a name.

        Args:
            name: The tool name

        Returns:
            Tool: A minimal STIX Tool object

        """
        now = datetime.now(tz=timezone.utc)
        tool_model = ToolModel(
            type="tool",
            spec_version="2.1",
            name=name,
            tool_types=[ToolTypeOV.UNKNOWN],
            created=now,
            modified=now,
            created_by_ref=self.organization.id,
            object_marking_refs=[self.tlp_marking.id],
        )
        return tool_model.to_stix2_object()

    @staticmethod
    def _extract_aliases(attributes: SoftwareToolkitModel) -> Optional[List[str]]:
        """Extract aliases from software toolkit attributes.

        Args:
            attributes: The software toolkit attributes

        Returns:
            Optional[List[str]]: Extracted aliases or None if no aliases exist

        """
        if (
            not hasattr(attributes, "alt_names_details")
            or not attributes.alt_names_details
        ):
            return None

        aliases = []
        for alt_name in attributes.alt_names_details:
            if hasattr(alt_name, "value") and alt_name.value:
                aliases.append(alt_name.value)

        return aliases if aliases else None

    def _extract_tool_types(
        self, attributes: SoftwareToolkitModel
    ) -> List[ToolTypeOV]:
        """Extract tool types from software toolkit attributes.

        Software toolkits are typically dual-use tools, so we default to
        "unknown" unless tags or malware_roles suggest otherwise.

        Args:
            attributes: The software toolkit attributes

        Returns:
            List[ToolTypeOV]: Extracted tool types

        """
        tool_types = []

        # Map known tags to tool types
        tag_to_tool_type = {
            "remote-access": ToolTypeOV.REMOTE_ACCESS,
            "remote access": ToolTypeOV.REMOTE_ACCESS,
            "credential": ToolTypeOV.CREDENTIAL_EXPLOITATION,
            "exploitation": ToolTypeOV.EXPLOITATION,
            "network-capture": ToolTypeOV.NETWORK_CAPTURE,
            "network capture": ToolTypeOV.NETWORK_CAPTURE,
            "recon": ToolTypeOV.INFORMATION_GATHERING,
            "reconnaissance": ToolTypeOV.INFORMATION_GATHERING,
            "information-gathering": ToolTypeOV.INFORMATION_GATHERING,
            "scanner": ToolTypeOV.VULNERABILITY_SCANNING,
            "dos": ToolTypeOV.DENIAL_OF_SERVICE,
            "denial-of-service": ToolTypeOV.DENIAL_OF_SERVICE,
        }

        # Map malware_roles to tool types
        role_to_tool_type = {
            "utility": ToolTypeOV.UNKNOWN,  # Generic utility
            "backdoor": ToolTypeOV.REMOTE_ACCESS,
            "dropper": ToolTypeOV.EXPLOITATION,
            "downloader": ToolTypeOV.EXPLOITATION,
            "loader": ToolTypeOV.EXPLOITATION,
            "rat": ToolTypeOV.REMOTE_ACCESS,
            "remote access tool": ToolTypeOV.REMOTE_ACCESS,
            "credential stealer": ToolTypeOV.CREDENTIAL_EXPLOITATION,
            "password dumper": ToolTypeOV.CREDENTIAL_EXPLOITATION,
        }

        if hasattr(attributes, "tags_details") and attributes.tags_details:
            for tag in attributes.tags_details:
                if hasattr(tag, "value") and tag.value:
                    tag_lower = tag.value.lower()
                    for keyword, tool_type in tag_to_tool_type.items():
                        if keyword in tag_lower and tool_type not in tool_types:
                            tool_types.append(tool_type)

        # Also check malware_roles for additional type hints
        if hasattr(attributes, "malware_roles") and attributes.malware_roles:
            for role in attributes.malware_roles:
                if hasattr(role, "value") and role.value:
                    role_lower = role.value.lower()
                    for keyword, tool_type in role_to_tool_type.items():
                        if keyword in role_lower and tool_type not in tool_types:
                            tool_types.append(tool_type)

        # Default to UNKNOWN if no types identified
        if not tool_types:
            tool_types.append(ToolTypeOV.UNKNOWN)

        return tool_types

    @staticmethod
    def _extract_labels(attributes: SoftwareToolkitModel) -> Optional[List[str]]:
        """Extract labels from software toolkit tag details.

        Args:
            attributes: The software toolkit attributes

        Returns:
            Optional[List[str]]: Extracted labels or None if no tags exist

        """
        if not hasattr(attributes, "tags_details") or not attributes.tags_details:
            return None

        labels = []
        for tag in attributes.tags_details:
            if hasattr(tag, "value") and tag.value:
                labels.append(tag.value)

        return labels if labels else None

    @staticmethod
    def _extract_capabilities(
        attributes: SoftwareToolkitModel,
    ) -> Optional[List[str]]:
        """Extract capability labels from software toolkit attributes.

        Capabilities are converted to labels prefixed with 'capability:' to
        distinguish them from tags.

        Args:
            attributes: The software toolkit attributes

        Returns:
            Optional[List[str]]: Capability labels or None if no capabilities exist

        """
        if not hasattr(attributes, "capabilities") or not attributes.capabilities:
            return None

        capability_labels = []
        for capability in attributes.capabilities:
            if hasattr(capability, "value") and capability.value:
                # Prefix with 'capability:' for clarity
                capability_labels.append(f"capability:{capability.value}")

        return capability_labels if capability_labels else None
