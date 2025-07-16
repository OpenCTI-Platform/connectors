"""Converts a GTI report's targeted regions to STIX Location objects."""

from typing import List, Optional

from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    TargetedRegion,
)
from connector.src.stix.octi.models.location_model import OctiLocationModel
from connector.src.stix.v21.models.ovs.region_ov_enums import RegionOV
from connector.src.utils.converters.generic_converter_config import BaseMapper
from stix2.v21 import Identity, Location, MarkingDefinition  # type: ignore


class GTIReportToSTIXLocation(BaseMapper):
    """Converts a GTI report's targeted regions to STIX Location objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: Identity,
        tlp_marking: MarkingDefinition,
    ):
        """Initialize the GTIReportToSTIXLocation object.

        Args:
            report (GTIReportData): The GTI report data to convert.
            organization (Identity): The organization identity object.
            tlp_marking (MarkingDefinition): The TLP marking definition.

        """
        self.report = report
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> List[Location]:
        """Convert the GTI report targeted regions to STIX Location objects.

        Returns:
            List[Location]: The list of STIX Location objects.

        """
        result: List[Location] = []

        if not hasattr(self.report, "attributes") or not self.report.attributes:
            raise ValueError("Invalid report attributes")

        targeted_regions = self.report.attributes.targeted_regions_hierarchy
        if not targeted_regions:
            return result

        for region_data in targeted_regions:
            location = self._process_region(region_data)
            if location:
                result.append(location)

        return result

    def _process_region(self, region_data: TargetedRegion) -> Optional[Location]:
        """Process a targeted region entry and convert to appropriate Location type.

        Args:
            region_data (TargetedRegion): The targeted region data to process.

        Returns:
            Optional[Location]: The STIX Location object, or None if no valid location found.

        """
        location = None
        if region_data.country:
            location = self._create_country(region_data)
        if location is None and region_data.sub_region:
            location = self._create_region(region_data, is_sub_region=True)
        if location is None and region_data.region:
            location = self._create_region(region_data, is_sub_region=False)

        return location

    def _create_country(self, region_data: TargetedRegion) -> Optional[Location]:
        """Create a LocationCountry object.

        Args:
            region_data (TargetedRegion): The targeted region data containing country information.

        Returns:
            Location: The STIX LocationCountry object.

        """
        if not region_data.country:
            return None

        iso_code = region_data.country_iso2
        if iso_code is None:
            return None

        country = OctiLocationModel.create_country(
            name=region_data.country,
            country_code=iso_code,
            description=region_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        country_stix = country.to_stix2_object()
        return country_stix

    def _create_region(
        self, region_data: TargetedRegion, is_sub_region: bool
    ) -> Optional[Location]:
        """Create a LocationRegion object.

        Args:
            region_data (TargetedRegion): The targeted region data containing region information.
            is_sub_region (bool): Whether to use the sub_region field (True) or region field (False).

        Returns:
            Location: The STIX LocationRegion object.

        """
        region_name = region_data.sub_region if is_sub_region else region_data.region
        if not region_name:
            return None

        # Normalize the region name for comparison
        normalized_name = region_name.lower().replace(" ", "-")

        # Check if the normalized name exists in the predefined RegionOV values
        predefined_values = [member.value for member in RegionOV]
        if normalized_name not in predefined_values:
            return None

        region_value = RegionOV(normalized_name)

        region = OctiLocationModel.create_region(
            name=region_name,
            region_value=region_value,
            description=region_data.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id],
        )

        region_stix = region

        return region_stix
