"""Shared converter class for common subentity conversion methods."""

import logging
from typing import Any, Dict, List, Optional

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXShared]"


class ConvertToSTIXShared(BaseConvertToSTIX):
    """Shared converter class for common subentity conversion methods."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Shared Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_subentities_to_stix(
        self, subentities: Dict[str, List[Any]], main_entity: Optional[str] = None
    ) -> List[Any]:
        """Convert each subentity to STIX format.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            main_entity: Type of the main entity

        Returns:
            List of converted STIX objects

        """
        self.logger.debug(f"{LOG_PREFIX} Starting subentity conversion")
        return super().convert_subentities_to_stix(subentities, main_entity)

    def convert_subentities_to_stix_with_linking(
        self,
        subentities: Dict[str, List[Any]],
        main_entity: str,
        main_entities: List[Any],
    ) -> Optional[List[Any]]:
        """Convert each subentity to STIX format with linking.

        Args:
            subentities: Dictionary mapping entity types to lists of entities
            main_entity: The main entity type
            main_entities: List containing the main entity STIX object

        Returns:
            List of converted STIX objects

        """
        self.logger.debug(f"{LOG_PREFIX} Starting subentity conversion with linking")
        return super().convert_subentities_to_stix_with_linking(
            subentities, main_entity, main_entities
        )
