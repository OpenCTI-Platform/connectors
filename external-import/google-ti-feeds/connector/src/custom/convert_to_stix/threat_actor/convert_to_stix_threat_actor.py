"""Threat actor-specific converter for fetching and processing threat actor data."""

import logging
from typing import Any, List

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXThreatActor]"


class ConvertToSTIXThreatActor(BaseConvertToSTIX):
    """Threat actor-specific converter for fetching and processing threat actor data."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Threat Actor Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_threat_actor_to_stix(self, threat_actor_data: Any) -> List[Any]:
        """Convert threat actor to location, identity, and threat actor STIX objects.

        Args:
            threat_actor_data: GTIThreatActorData object from fetcher

        Returns:
            List of STIX entities (location, identity, threat_actor)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("threat_actor")
            stix_entities = converter.convert_single(threat_actor_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                "Converted threat actor to STIX entities",
                {"prefix": LOG_PREFIX, "entity_count": len(stix_entities)},
            )
            return stix_entities

        except Exception as e:
            self.logger.error(
                "Failed to convert threat actor to STIX",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return []
