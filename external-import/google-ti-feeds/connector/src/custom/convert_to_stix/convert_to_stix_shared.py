"""Shared converter class for common subentity conversion methods."""

import logging
from typing import Any

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXShared]"


class ConvertToSTIXShared(BaseConvertToSTIX):
    """Shared converter class for common subentity conversion methods."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Shared Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_subentities_to_stix(
        self, subentities: dict[str, list[Any]], main_entity: str | None = None
    ) -> list[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            list of converted STIX objects

        """
        self.logger.debug("Starting subentity conversion", {"prefix": LOG_PREFIX})
        return super().convert_subentities_to_stix(subentities, main_entity)

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: dict[str, list[Any]],
        main_entity: str,
        main_entities: list[Any],
    ) -> list[Any] | None:
        """Convert each subentity to STIX format with linking.

        Args:
            subentities: dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: list containing the main entity STIX object

        Returns:
            list of converted STIX objects

        """
        self.logger.debug(
            "Starting subentity conversion with linking", {"prefix": LOG_PREFIX}
        )
        return super().convert_subentities_to_stix_with_linking(
            subentities, main_entity, main_entities
        )
