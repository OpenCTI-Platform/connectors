"""Converts a GTI report's targeted industries to STIX Identity objects as sectors."""

from typing import List, Optional

from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    TargetedIndustry,
)
from connector.src.stix.octi.models.identity_sector_model import OctiIdentitySectorModel
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class GTIReportToSTIXSector(BaseMapper):
    """Converts a GTI report's targeted industries to STIX Identity objects as sectors."""

    def __init__(
        self,
        report: GTIReportData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ):
        """Initialize the GTIReportToSTIXSector object.

        Args:
            report (GTIReportData): The GTI report data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.report = report
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Identity]:
        """Convert the GTI report targeted industries to STIX Identity objects.

        Returns:
            List[Identity]: The list of STIX Identity objects representing sectors.

        """
        result: List[Identity] = []
        if not hasattr(self.report, "attributes") or not self.report.attributes:
            raise ValueError("Invalid report attributes")

        targeted_industries = self.report.attributes.targeted_industries_tree
        if not targeted_industries:
            return result

        for industry_data in targeted_industries:
            sector = self._process_industry(industry_data)
            if sector:
                result.append(sector)

        return result

    def _process_industry(self, industry_data: TargetedIndustry) -> Optional[Identity]:
        """Process a targeted industry entry and convert to a sector Identity.

        Args:
            industry_data (TargetedIndustry): The targeted industry data to process.

        Returns:
            Optional[Identity]: The STIX Identity object, or None if no valid industry group found.

        """
        if not industry_data.industry_group:
            return None

        return self._create_sector(industry_data)

    def _create_sector(self, industry_data: TargetedIndustry) -> Identity:
        """Create a Sector Identity object.

        Args:
            industry_data (TargetedIndustry): The targeted industry data containing industry group information.

        Returns:
            Identity: The STIX Identity object representing a sector.

        """
        sector_name = industry_data.industry_group

        sector = OctiIdentitySectorModel.create(
            name=sector_name,
            description=industry_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        sector_stix = sector

        return sector_stix
