"""Composite mapper that handles software toolkit to country locations, identity, tool, and relationships conversion in one step."""

from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_identity import (
    GTISoftwareToolkitToSTIXIdentity,
    IdentityWithTiming,
)
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_location import (
    GTISoftwareToolkitToSTIXLocation,
    LocationWithTiming,
)
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_tool import (
    GTISoftwareToolkitToSTIXTool,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
)
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
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

        targeted_locations_with_timing = self._get_targeted_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in targeted_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=tool.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
            )
            relationships.append(relationship)

        source_locations_with_timing = self._get_source_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in source_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=tool.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
            )
            relationships.append(relationship)

        for sector_with_timing in sectors_with_timing:
            sector = sector_with_timing.identity
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=tool.id,
                target_ref=sector.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=sector_with_timing.first_seen,
                stop_time=sector_with_timing.last_seen,
            )
            relationships.append(relationship)

        return relationships

    def _get_targeted_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to targeted countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to targeted countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_targeted
        ]

    def _get_source_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to source countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to source countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_source
        ]
