"""Fetcher factory for creating entity fetchers.

This module provides a factory class for creating entity fetchers with the
appropriate configuration, eliminating the need for separate specialized
fetcher classes.
"""

import logging
from typing import Dict, Optional

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.fetchers.entity_config import (
    ENTITY_CONFIGS,
)
from connector.src.custom.fetchers.generic_entity_fetcher import GenericEntityFetcher
from connector.src.utils.api_engine.api_client import ApiClient


class FetcherFactory:
    """Factory for creating entity fetchers with appropriate configuration."""

    @classmethod
    def create_entity_fetcher(
        cls,
        entity_type: str,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ) -> GenericEntityFetcher:
        """Create an entity fetcher for the specified type.

        Args:
            entity_type: Type of entity to create fetcher for (e.g., "malware_families")
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            logger: Logger for logging messages

        Returns:
            Configured generic entity fetcher for the specified entity type

        Raises:
            ValueError: If the entity type is not supported

        """
        if entity_type not in ENTITY_CONFIGS:
            available_types = ", ".join(ENTITY_CONFIGS.keys())
            raise ValueError(
                f"Unsupported entity type '{entity_type}'. Available types: {available_types}"
            )

        config = ENTITY_CONFIGS[entity_type]
        return GenericEntityFetcher(config, gti_config, api_client, logger)

    @classmethod
    def get_available_entity_types(cls) -> list[str]:
        """Get list of available entity types.

        Returns:
            List of supported entity type names

        """
        return list(ENTITY_CONFIGS.keys())

    @classmethod
    def create_all_entity_fetchers(
        cls,
        gti_config: GTIConfig,
        api_client: ApiClient,
        logger: Optional[logging.Logger] = None,
    ) -> Dict[str, GenericEntityFetcher]:
        """Create fetchers for all supported entity types.

        Args:
            gti_config: Configuration for accessing the GTI API
            api_client: Client for making API requests
            logger: Logger for logging messages

        Returns:
            Dictionary mapping entity type names to configured fetchers

        """
        return {
            entity_type: cls.create_entity_fetcher(
                entity_type, gti_config, api_client, logger
            )
            for entity_type in ENTITY_CONFIGS.keys()
        }
