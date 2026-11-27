"""Composite mapper that handles software toolkit to country locations, identity, tool, and relationships conversion in one step."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_identity import (
    GTISoftwareToolkitToSTIXIdentity,
)
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_location import (
    GTISoftwareToolkitToSTIXLocation,
)
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_tool import (
    GTISoftwareToolkitToSTIXTool,
)
from connector.src.custom.mappers.targeting_mappers import targeting_relationships
from connector.src.custom.mappers.timing_models import (
    IdentityWithTiming,
    LocationWithTiming,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models import (
    OrganizationAuthor,
    TLPMarking,
)


class GTISoftwareToolkitToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI software toolkit to country locations, identity, tool, and relationships."""

    def __init__(
        self,
        software_toolkit: GTISoftwareToolkitData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            software_toolkit: The GTI software toolkit data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition

        """
        self.software_toolkit = software_toolkit
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> list[Any]:
        """Convert the GTI software toolkit to a list of STIX objects (country locations, sectors, tool, relationships).

        Returns:
            list of STIX objects in order: [country_locations..., sectors..., tool, relationships...]

        """
        all_entities = []

        location_mapper = GTISoftwareToolkitToSTIXLocation(
            software_toolkit=self.software_toolkit,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations_with_timing = location_mapper.to_stix_with_timing()
        country_locations = [item.location for item in locations_with_timing]
        all_entities.extend(country_locations)

        identity_mapper = GTISoftwareToolkitToSTIXIdentity(
            software_toolkit=self.software_toolkit,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors_with_timing = identity_mapper.to_stix_with_timing()
        sectors = [item.identity for item in sectors_with_timing]
        all_entities.extend(sectors)

        tool_mapper = GTISoftwareToolkitToSTIXTool(
            software_toolkit=self.software_toolkit,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        tool = tool_mapper.to_stix()
        all_entities.append(tool)

        relationships = self._create_relationships(
            tool, locations_with_timing, sectors_with_timing
        )
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self,
        tool: Any,
        locations_with_timing: list[LocationWithTiming],
        sectors_with_timing: list[IdentityWithTiming],
    ) -> list[Any]:
        """Create relationships between the tool and other entities.

        Args:
            tool: The tool object
            locations_with_timing: list of LocationWithTiming objects containing location and timing data
            sectors_with_timing: list of IdentityWithTiming objects containing sector identity and timing data

        Returns:
            list of relationship objects

        """
        relationships: list[Any] = []

        if (
            not hasattr(self.software_toolkit, "attributes")
            or not self.software_toolkit.attributes
        ):
            return relationships

        attributes = self.software_toolkit.attributes
        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        relationships.extend(
            targeting_relationships(
                tool,
                locations_with_timing,
                sectors_with_timing,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
            )
        )

        return relationships
