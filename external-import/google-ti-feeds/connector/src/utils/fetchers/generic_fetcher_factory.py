"""Generic fetcher factory for creating API fetchers with flexible configuration.

This module provides a factory class for creating generic API fetchers that can
work with any endpoint, response model, and exception handling configuration.
"""

import logging
from typing import Any, Dict, List, Optional, Type

from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.fetchers.generic_fetcher import GenericFetcher
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

LOG_PREFIX = "[GenericFetcherFactory]"


class GenericFetcherFactory:
    """Factory for creating generic API fetchers with flexible configuration."""

    def __init__(
        self,
        api_client: ApiClient,
        base_headers: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the factory with common dependencies.

        Args:
            api_client: Client for making API requests
            base_headers: Base headers to include in all requests
            logger: Logger for logging messages

        """
        self.api_client = api_client
        self.base_headers = base_headers or {}
        self.logger = logger or logging.getLogger(__name__)
        self._fetcher_registry: Dict[str, GenericFetcherConfig] = {}

    def register_config(self, name: str, config: GenericFetcherConfig) -> None:
        """Register a fetcher configuration with a name.

        Args:
            name: Name to register the configuration under
            config: The fetcher configuration to register

        """
        self._fetcher_registry[name] = config
        self.logger.debug(
            f"{LOG_PREFIX} Registered fetcher config '{name}' for entity type '{config.entity_type}'"
        )

    def create_fetcher(
        self,
        config: GenericFetcherConfig,
        additional_headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
    ) -> GenericFetcher:
        """Create a fetcher with the provided configuration.

        Args:
            config: Configuration for the fetcher
            additional_headers: Additional headers specific to this fetcher
            base_url: Optional base URL to prepend to endpoints

        Returns:
            Configured generic fetcher

        """
        merged_headers = {}
        merged_headers.update(self.base_headers)
        if additional_headers:
            merged_headers.update(additional_headers)

        return GenericFetcher(
            config=config,
            api_client=self.api_client,
            base_headers=merged_headers,
            base_url=base_url,
            logger=self.logger,
        )

    def create_fetcher_by_name(
        self,
        name: str,
        additional_headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
    ) -> GenericFetcher:
        """Create a fetcher using a registered configuration.

        Args:
            name: Name of the registered configuration
            additional_headers: Additional headers specific to this fetcher
            base_url: Optional base URL to prepend to endpoints

        Returns:
            Configured generic fetcher

        Raises:
            ValueError: If the configuration name is not registered

        """
        if name not in self._fetcher_registry:
            available_configs = ", ".join(self._fetcher_registry.keys())
            raise ValueError(
                f"No fetcher configuration registered for '{name}'. "
                f"Available configurations: {available_configs}"
            )

        config = self._fetcher_registry[name]
        return self.create_fetcher(config, additional_headers, base_url)

    def create_simple_fetcher(
        self,
        entity_type: str,
        endpoint: str,
        display_name: str,
        exception_class: Type[Exception],
        response_model: Optional[Type[Any]] = None,
        method: str = "GET",
        additional_headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
        **config_kwargs: Any,
    ) -> GenericFetcher:
        """Create a fetcher with a simple inline configuration.

        Args:
            entity_type: The type of entity being fetched
            endpoint: The API endpoint URL or template
            display_name: Human-readable name for logging
            exception_class: Exception class to raise on errors
            response_model: Optional response model for parsing
            method: HTTP method to use
            additional_headers: Additional headers for this fetcher
            base_url: Optional base URL to prepend to endpoints
            **config_kwargs: Additional configuration parameters

        Returns:
            Configured generic fetcher

        """
        config = GenericFetcherConfig(
            entity_type=entity_type,
            endpoint=endpoint,
            display_name=display_name,
            exception_class=exception_class,
            response_model=response_model,
            method=method,
            **config_kwargs,
        )

        return self.create_fetcher(config, additional_headers, base_url)

    def get_registered_configs(self) -> Dict[str, GenericFetcherConfig]:
        """Get all registered fetcher configurations.

        Returns:
            Dictionary mapping configuration names to their configs

        """
        return self._fetcher_registry.copy()

    def get_available_config_names(self) -> List[str]:
        """Get list of available configuration names.

        Returns:
            List of registered configuration names

        """
        return list(self._fetcher_registry.keys())

    def create_multiple_fetchers(
        self, config_names: List[str], base_url: Optional[str] = None
    ) -> Dict[str, GenericFetcher]:
        """Create multiple fetchers from registered configurations.

        Args:
            config_names: List of configuration names to create fetchers for
            base_url: Optional base URL to prepend to all endpoints

        Returns:
            Dictionary mapping configuration names to fetchers

        Raises:
            ValueError: If any configuration name is not registered

        """
        fetchers = {}
        for name in config_names:
            fetchers[name] = self.create_fetcher_by_name(name, base_url=base_url)
        return fetchers

    def create_all_registered_fetchers(
        self, base_url: Optional[str] = None
    ) -> Dict[str, GenericFetcher]:
        """Create fetchers for all registered configurations.

        Args:
            base_url: Optional base URL to prepend to all endpoints

        Returns:
            Dictionary mapping configuration names to fetchers

        """
        return {
            name: self.create_fetcher_by_name(name, base_url=base_url)
            for name in self._fetcher_registry.keys()
        }
