"""Composite mapper that handles report to locations, identity, and report conversion in one step."""

from datetime import datetime, timezone
from typing import Any

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
from connector.src.custom.models.gti.gti_report_model import GTIReportData
from connector.src.stix.octi.models.note_model import OctiNoteModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIReportToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI report to locations, identity, and report STIX objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
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

    def to_stix(self) -> list[Any]:
        """Convert the GTI report to a list of STIX objects (locations, sectors, identity, report).

        Returns:
            list of STIX objects in order: [locations..., sectors..., identity, report]

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

        note = self._create_analyst_comment_note(report_stix)
        if note is not None:
            all_entities.append(note)

        return all_entities

    def _create_analyst_comment_note(self, report_stix: Any) -> Any:
        """Create a STIX Note from the analyst_comment field if present.

        Args:
            report_stix: The STIX report object to attach the note to

        Returns:
            A STIX Note object, or None if no analyst_comment is present

        """
        attributes = self.report.attributes
        if not attributes or not attributes.analyst_comment:
            return None

        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        note_model = OctiNoteModel.create(
            content=attributes.analyst_comment,
            abstract=f"Analyst Comment & News Analysis Rating - {attributes.name}",
            created=created,
            modified=modified,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
            object_refs=[report_stix.id],
            authors=["Google Threat Intelligence"],
        )

        return note_model.to_stix2_object()
