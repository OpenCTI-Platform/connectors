"""Composite mapper that handles report to locations, identity, and report conversion in one step."""

import uuid
from typing import Any, Dict, List, Optional

from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_sector import (
    GTIReportToSTIXSector,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    Technology,
)
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition, Software  # type: ignore


class GTIReportToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI report to locations, identity, and report STIX objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
        **kwargs: Any,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            report: The GTI report data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition

        """
        self.report = report
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Any]:
        """Convert the GTI report to a list of STIX objects (locations, sectors, identity, report).

        Returns:
            List of STIX objects in order: [locations..., sectors..., identity, report]

        """
        all_entities = []

        location_mapper = GTIReportToSTIXLocation(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations = location_mapper.to_stix()
        all_entities.extend(locations)

        sector_mapper = GTIReportToSTIXSector(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors = sector_mapper.to_stix()
        all_entities.extend(sectors)

        identity_mapper = GTIReportToSTIXIdentity(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        author_identity = identity_mapper.to_stix()
        all_entities.append(author_identity)

        report_mapper = GTIReportToSTIXReport(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )

        report_mapper.add_author_identity(author_identity)

        report_stix = report_mapper.to_stix()

        location_ids = [loc.id for loc in locations]
        sector_ids = [sector.id for sector in sectors]

        report_stix = GTIReportToSTIXReport.add_object_refs(location_ids, report_stix)
        report_stix = GTIReportToSTIXReport.add_object_refs(sector_ids, report_stix)

        # Extract Software objects from technologies
        software_objects = self._extract_technologies()
        all_entities.extend(software_objects)
        software_ids = [sw.id for sw in software_objects]
        report_stix = GTIReportToSTIXReport.add_object_refs(software_ids, report_stix)

        all_entities.append(report_stix)

        return all_entities

    def _extract_technologies(self) -> List[Software]:
        """Extract Software objects from report technologies.

        Returns:
            List[Software]: STIX Software objects for affected technologies

        """
        if (
            not self.report.attributes
            or not self.report.attributes.technologies
        ):
            return []

        software_objects: List[Software] = []
        seen_keys: set = set()

        for tech in self.report.attributes.technologies:
            software = self._create_software(tech, seen_keys)
            if software:
                software_objects.append(software)

        return software_objects

    def _create_software(
        self, tech: Technology, seen_keys: set
    ) -> Optional[Software]:
        """Create a STIX Software object from a Technology.

        Args:
            tech: The technology data
            seen_keys: Set of already-seen keys to avoid duplicates

        Returns:
            Optional[Software]: A Software object or None if insufficient data

        """
        # Determine name: prefer cpe_title, fall back to technology_name
        name = tech.cpe_title or tech.technology_name
        if not name:
            return None

        # Dedup key
        dedup_key = tech.cpe or name.lower()
        if dedup_key in seen_keys:
            return None
        seen_keys.add(dedup_key)

        # Build software kwargs
        software_kwargs: Dict[str, Any] = {"name": name}
        if tech.cpe:
            software_kwargs["cpe"] = tech.cpe
        if tech.vendor:
            software_kwargs["vendor"] = tech.vendor

        # Generate deterministic ID
        software_kwargs["id"] = self._generate_software_id(
            name=name, cpe=tech.cpe, vendor=tech.vendor
        )

        return Software(**software_kwargs)

    @staticmethod
    def _generate_software_id(
        name: str,
        cpe: Optional[str] = None,
        vendor: Optional[str] = None,
    ) -> str:
        """Generate a deterministic STIX ID for a Software object.

        Args:
            name: The software name
            cpe: Optional CPE URI
            vendor: Optional vendor name

        Returns:
            str: A deterministic software ID

        """
        stix_namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

        if cpe:
            id_source = f"software:{cpe}"
        else:
            parts = ["software", name.lower()]
            if vendor:
                parts.append(vendor.lower())
            id_source = ":".join(parts)

        software_uuid = uuid.uuid5(stix_namespace, id_source)
        return f"software--{software_uuid}"
