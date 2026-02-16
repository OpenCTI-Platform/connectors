"""Threat actor-specific converter for fetching and processing threat actor data."""

import logging
from typing import Any

from connector.src.custom.configs import (
    GTIConfig,
)
from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXThreatActor]"


class ConvertToSTIXThreatActor(BaseConvertToSTIX):
    """Threat actor-specific converter for fetching and processing threat actor data."""

    def __init__(self, config: GTIConfig, logger: logging.Logger, tlp_level: str):
        """Initialize Threat Actor Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_threat_actor_to_stix(self, threat_actor_data: Any) -> list[Any]:
        """Convert threat actor to location, identity, and threat actor STIX objects.

        Args:
            threat_actor_data: GTIThreatActorData object from fetcher

        Returns:
            list of STIX entities (location, identity, threat_actor)

        """
        try:
            additional_deps = {}
            if hasattr(self.config, "enable_threat_actor_aliases"):
                additional_deps["enable_threat_actor_aliases"] = (
                    self.config.enable_threat_actor_aliases
                )

            converter = self.converter_factory.create_converter_by_name(
                "threat_actor", additional_dependencies=additional_deps
            )
            stix_entities = converter.convert_single(threat_actor_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                "Converted threat actor to STIX entities",
                {"prefix": LOG_PREFIX, "entity_count": len(stix_entities)},
            )
            return stix_entities

        except Exception as e:
            self.logger.warning(
                "Failed to convert threat actor to STIX",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return []
