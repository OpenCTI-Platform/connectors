"""Composite mapper that handles report to locations, identity, and report conversion in one step."""

from typing import Any, List

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
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIReportToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI report to locations, identity, and report STIX objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
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

        all_entities.append(report_stix)

        return all_entities
