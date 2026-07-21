"""Software toolkit-specific converter for processing software toolkit data."""

import logging
from typing import Any

from connector.src.custom.configs import (
    GTIConfig,
)
from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXSoftwareToolkit]"


class ConvertToSTIXSoftwareToolkit(BaseConvertToSTIX):
    """Software toolkit-specific converter for processing software toolkit data."""

    def __init__(self, config: GTIConfig, logger: logging.Logger, tlp_level: str):
        """Initialize Software Toolkit Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_software_toolkit_to_stix(self, software_toolkit_data: Any) -> list[Any]:
        """Convert software toolkit to a STIX Tool object.

        Args:
            software_toolkit_data: GTISoftwareToolkitData object from fetcher

        Returns:
            list of STIX entities (tool)

        """
        try:
            converter = self.converter_factory.create_converter_by_name(
                "software_toolkit"
            )
            stix_entities = converter.convert_single(software_toolkit_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                "Converted software toolkit to STIX entities",
                {"prefix": LOG_PREFIX, "entity_count": len(stix_entities)},
            )
            return stix_entities

        except Exception as e:
            self.logger.warning(
                "Failed to convert software toolkit to STIX",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return []
