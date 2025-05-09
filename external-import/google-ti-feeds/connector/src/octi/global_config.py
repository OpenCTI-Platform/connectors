"""Handles the global configuration for the connector."""

from typing import TYPE_CHECKING, Any, Type

from pydantic_core import ValidationError

from connector.src.octi.configs.connector_config import ConnectorConfig
from connector.src.octi.configs.octi_config import OctiConfig
from connector.src.octi.exceptions.configuration_error import ConfigurationError

if TYPE_CHECKING:
    from connector.src.octi.interfaces.base_config import BaseConfig


class GlobalConfig:
    """Global configuration for the connector."""

    def __init__(self) -> None:
        """Initialize the global configuration."""
        #    self.load_config()

        self.instanciate_configs: dict[str, Any] = {}
        try:
            self.octi_config = OctiConfig()
        except ValidationError as e:
            raise ConfigurationError(
                "Error loading the OpenCTI configuration", errors=e.errors
            ) from e
        try:
            self.connector_config = ConnectorConfig()
        except ValidationError as e:
            raise ConfigurationError(
                "Error loading the connector configuration", errors=e.errors
            ) from e

        self.instanciate_configs.update(
            {"opencti": self.octi_config.model_dump(exclude_none=True)}
        )
        self.instanciate_configs.update(
            {"connector": self.connector_config.model_dump(exclude_none=True)}
        )

        self.to_dict()

    def add_config_class(self, config_class: Type["BaseConfig"]) -> None:
        """Add a configuration class to the global configuration."""
        try:
            config_instance = config_class()
        except ValidationError as e:
            raise ConfigurationError(
                f"Error loading the {config_class.__name__} configuration",
                errors=e.errors,
            ) from e
        self.instanciate_configs.update(
            {
                config_class.__name__.lower(): config_instance.model_dump(
                    exclude_none=True
                )
            }
        )

        self.to_dict()

    def get_config_class(self, config_class: Type["BaseConfig"]) -> Any:
        """Get a configuration class from the global configuration."""
        config_name = config_class.__name__.lower()
        if config_name in self.instanciate_configs:
            return self.instanciate_configs[config_name]
        else:
            raise ConfigurationError(
                f"Configuration class {config_name} not found in global configuration."
            )

    def to_dict(self) -> dict[str, dict[str, Any]]:
        """Convert the configuration to a dictionary."""
        dicc: dict[str, dict[str, Any]] = {}
        for key, value in self.instanciate_configs.items():
            dicc.update({key: value})

        return dicc
