"""Generic converter factory for creating STIX converters with flexible configuration.

This module provides a factory class for creating generic STIX converters that can
work with any input data format, mapper class, and output STIX entity type.
"""

import logging
from typing import Any, Dict, List, Optional, Type

from connector.src.utils.converters.generic_converter import GenericConverter
from connector.src.utils.converters.generic_converter_config import (
    BaseMapper,
    GenericConverterConfig,
)
from pydantic import BaseModel

LOG_PREFIX = "[GenericConverterFactory]"


class GenericConverterFactory:
    """Factory for creating generic STIX converters with flexible configuration."""

    def __init__(
        self,
        global_dependencies: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the factory with common dependencies.

        Args:
            global_dependencies: Global dependencies to include in all converters (e.g., organization, tlp_marking)
            logger: Logger for logging messages

        """
        self.global_dependencies = global_dependencies or {}
        self.logger = logger or logging.getLogger(__name__)
        self._converter_registry: Dict[str, GenericConverterConfig] = {}

    def register_config(self, name: str, config: GenericConverterConfig) -> None:
        """Register a converter configuration with a name.

        Args:
            name: Name to register the configuration under
            config: The converter configuration to register

        """
        self._converter_registry[name] = config
        self.logger.debug(
            f"{LOG_PREFIX} Registered converter config '{name}' for entity type '{config.entity_type}'"
        )

    def create_converter(
        self,
        config: GenericConverterConfig,
        additional_dependencies: Optional[Dict[str, Any]] = None,
    ) -> GenericConverter:
        """Create a converter with the provided configuration.

        Args:
            config: Configuration for the converter
            additional_dependencies: Additional dependencies specific to this converter

        Returns:
            Configured generic converter

        """
        merged_config = self._merge_dependencies(config, additional_dependencies)

        return GenericConverter(
            config=merged_config,
            logger=self.logger,
        )

    def create_converter_by_name(
        self,
        name: str,
        additional_dependencies: Optional[Dict[str, Any]] = None,
    ) -> GenericConverter:
        """Create a converter using a registered configuration.

        Args:
            name: Name of the registered configuration
            additional_dependencies: Additional dependencies specific to this converter

        Returns:
            Configured generic converter

        Raises:
            ValueError: If the configuration name is not registered

        """
        if name not in self._converter_registry:
            available_configs = ", ".join(self._converter_registry.keys())
            raise ValueError(
                f"No converter configuration registered for '{name}'. "
                f"Available configurations: {available_configs}"
            )

        config = self._converter_registry[name]
        return self.create_converter(config, additional_dependencies)

    def create_simple_converter(
        self,
        entity_type: str,
        mapper_class: Type[BaseMapper],
        output_stix_type: str,
        exception_class: Type[Exception],
        display_name: str,
        input_model: Optional[Type[BaseModel]] = None,
        additional_dependencies: Optional[Dict[str, Any]] = None,
        **config_kwargs: Any,
    ) -> GenericConverter:
        """Create a converter with a simple inline configuration.

        Args:
            entity_type: The type of entity being converted
            mapper_class: The mapper class for conversion
            output_stix_type: The STIX object type being produced
            exception_class: Exception class to raise on errors
            display_name: Human-readable name for logging
            input_model: Optional input model type for validation
            additional_dependencies: Additional dependencies for this converter
            **config_kwargs: Additional configuration parameters

        Returns:
            Configured generic converter

        """
        config = GenericConverterConfig(
            entity_type=entity_type,
            mapper_class=mapper_class,
            output_stix_type=output_stix_type,
            exception_class=exception_class,
            display_name=display_name,
            input_model=input_model,
            **config_kwargs,
        )

        return self.create_converter(config, additional_dependencies)

    def get_registered_configs(self) -> Dict[str, GenericConverterConfig]:
        """Get all registered converter configurations.

        Returns:
            Dictionary mapping configuration names to their configs

        """
        return self._converter_registry.copy()

    def get_available_config_names(self) -> List[str]:
        """Get list of available configuration names.

        Returns:
            List of registered configuration names

        """
        return list(self._converter_registry.keys())

    def create_multiple_converters(
        self, config_names: List[str]
    ) -> Dict[str, GenericConverter]:
        """Create multiple converters from registered configurations.

        Args:
            config_names: List of configuration names to create converters for

        Returns:
            Dictionary mapping configuration names to converters

        Raises:
            ValueError: If any configuration name is not registered

        """
        converters = {}
        for name in config_names:
            converters[name] = self.create_converter_by_name(name)
        return converters

    def create_all_registered_converters(self) -> Dict[str, GenericConverter]:
        """Create converters for all registered configurations.

        Returns:
            Dictionary mapping configuration names to converters

        """
        return {
            name: self.create_converter_by_name(name)
            for name in self._converter_registry.keys()
        }

    def create_conversion_pipeline(
        self,
        converter_names: List[str],
        shared_dependencies: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, GenericConverter]:
        """Create a pipeline of converters for batch processing.

        Args:
            converter_names: List of converter configuration names
            shared_dependencies: Dependencies shared across all converters in the pipeline

        Returns:
            Dictionary mapping converter names to converter instances

        Raises:
            ValueError: If any converter name is not registered

        """
        pipeline = {}

        for name in converter_names:
            if name not in self._converter_registry:
                available_configs = ", ".join(self._converter_registry.keys())
                raise ValueError(
                    f"No converter configuration registered for '{name}'. "
                    f"Available configurations: {available_configs}"
                )

            merged_deps = {**self.global_dependencies}
            if shared_dependencies:
                merged_deps.update(shared_dependencies)

            config = self._converter_registry[name]
            merged_config = self._merge_dependencies(config, merged_deps)

            pipeline[name] = GenericConverter(
                config=merged_config,
                logger=self.logger,
            )

        self.logger.info(
            f"{LOG_PREFIX} Created conversion pipeline with {len(pipeline)} converters: {', '.join(converter_names)}"
        )
        return pipeline

    def register_batch_configs(
        self, configs: Dict[str, GenericConverterConfig]
    ) -> None:
        """Register multiple converter configurations at once.

        Args:
            configs: Dictionary mapping configuration names to configs

        """
        for name, config in configs.items():
            self.register_config(name, config)

        self.logger.info(
            f"{LOG_PREFIX} Registered {len(configs)} converter configurations: {', '.join(configs.keys())}"
        )

    def _merge_dependencies(
        self,
        config: GenericConverterConfig,
        additional_dependencies: Optional[Dict[str, Any]] = None,
    ) -> GenericConverterConfig:
        """Merge global and additional dependencies into the configuration.

        Args:
            config: The original configuration
            additional_dependencies: Additional dependencies to merge

        Returns:
            New configuration with merged dependencies

        """
        merged_deps = {**self.global_dependencies}

        if config.additional_dependencies:
            merged_deps.update(config.additional_dependencies)

        if additional_dependencies:
            merged_deps.update(additional_dependencies)

        return GenericConverterConfig(
            entity_type=config.entity_type,
            mapper_class=config.mapper_class,
            output_stix_type=config.output_stix_type,
            exception_class=config.exception_class,
            display_name=config.display_name,
            input_model=config.input_model,
            display_name_singular=config.display_name_singular,
            validate_input=config.validate_input,
            validate_output=config.validate_output,
            additional_dependencies=merged_deps,
            id_field=config.id_field,
            name_field=config.name_field,
            required_attributes=config.required_attributes,
            preprocessing_function=config.preprocessing_function,
            postprocessing_function=config.postprocessing_function,
        )
