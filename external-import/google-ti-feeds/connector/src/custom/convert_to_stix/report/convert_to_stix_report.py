"""Report-specific converter for fetching and processing report data."""

import logging
from typing import Any

from connector.src.custom.configs import (
    GTIConfig,
)
from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXReport]"


class ConvertToSTIXReport(BaseConvertToSTIX):
    """Report-specific converter for fetching and processing report data."""

    def __init__(self, config: GTIConfig, logger: logging.Logger, tlp_level: str):
        """Initialize Report Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_report_to_stix(self, report_data: Any) -> list[Any]:
        """Convert report to location, identity, and report STIX objects.

        Args:
            report_data: GTIReportData object from fetcher

        Returns:
            list of STIX entities (location, identity, report)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("reports")
            stix_entities = converter.convert_single(report_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                "Converted report to STIX entities",
                {"prefix": LOG_PREFIX, "entity_count": len(stix_entities)},
            )
            return stix_entities

        except Exception as e:
            self.logger.warning(
                "Failed to convert report to STIX",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return []
