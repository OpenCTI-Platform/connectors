"""Converts a GTI software toolkit to a STIX Tool object."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
    SoftwareToolkitModel,
)
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import ExternalReference, Tool
from connectors_sdk.models.enums import ToolType
from connectors_sdk.models.octi import (
    OrganizationAuthor,
    TLPMarking,
)
from stix2.v21 import Tool as Stix2Tool


class GTISoftwareToolkitToSTIXTool(BaseMapper):
    """Converts a GTI software toolkit to a STIX Tool object."""

    @staticmethod
    def create_relationship(
        src_entity: Any, relation_type: str, target_entity: Any
    ) -> Any:
        """Create a relationship between an entity and a tool.

        Args:
            src_entity: The source entity
            relation_type: The relationship type (e.g. 'uses')
            target_entity: The target entity

        Returns:
            OctiRelationshipModel: The relationship object, or None if neither entity is a Tool

        """
        if not any(
            "Tool" in str(type(entity).__name__)
            for entity in [src_entity, target_entity]
        ):
            return None

        return OctiRelationshipModel.create(
            relationship_type=relation_type,
            source_ref=src_entity.id,
            target_ref=target_entity.id,
            organization_id=src_entity.created_by_ref,
            marking_ids=src_entity.object_marking_refs,
            created=datetime.now(tz=timezone.utc),
            modified=datetime.now(tz=timezone.utc),
        )

    def __init__(
        self,
        software_toolkit: GTISoftwareToolkitData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the GTISoftwareToolkitToSTIXTool object.

        Args:
            software_toolkit: The GTI software toolkit data to convert.
            organization: The organization author object.
            tlp_marking: The TLP marking definition.

        """
        self.software_toolkit = software_toolkit
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> Stix2Tool:
        """Convert the GTI software toolkit to a STIX Tool object.

        Returns:
            Tool: The STIX Tool object.

        """
        if not self.software_toolkit or not self.software_toolkit.attributes:
            raise ValueError("Software toolkit attributes are missing")

        attributes = self.software_toolkit.attributes

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)

        aliases = self._extract_aliases(attributes)

        tool_types = self._extract_malware_types_as_tool_types(attributes)

        external_references = self._create_external_references()

        tool_model = Tool(
            name=attributes.name,
            author=self.organization,
            markings=[self.tlp_marking],
            description=attributes.description,
            tool_types=tool_types if tool_types else None,
            aliases=aliases,
            created=created,
            external_references=external_references,
        )

        return tool_model.to_stix2_object()

    @staticmethod
    def _extract_aliases(attributes: SoftwareToolkitModel) -> list[str] | None:
        """Extract aliases from software toolkit attributes.

        Args:
            attributes: The software toolkit attributes

        Returns:
            list[str] | None: Extracted alias values or None if no aliases exist

        """
        if not attributes.alt_names_details:
            return None
        return [detail.value for detail in attributes.alt_names_details if detail.value]

    def _extract_malware_types_as_tool_types(
        self, attributes: SoftwareToolkitModel
    ) -> list[ToolType]:
        """Extract malware types from software toolkit attributes.

        Args:
            attributes: The software toolkit attributes

        Returns:
            list[MalwareTypeOV]: Extracted malware types

        """
        malware_types = []
        if hasattr(attributes, "malware_roles") and attributes.malware_roles:
            for role in attributes.malware_roles:
                if hasattr(role, "value") and role.value:
                    malware_types.append(ToolType(role.value))

        return malware_types

    def _create_external_references(self) -> list[ExternalReference] | None:
        """Create external references pointing to the GTI software toolkit page.

        Returns:
            list[ExternalReference] | None: External references or None if no ID available

        """
        toolkit_id = self.software_toolkit.id
        if not toolkit_id:
            return None

        return [
            ExternalReference(
                source_name="Google Threat Intelligence",
                url=f"https://www.virustotal.com/gui/collection/{toolkit_id}",
                external_id=toolkit_id,
            )
        ]
