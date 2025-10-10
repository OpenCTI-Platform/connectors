"""Base configuration models for connectors.

This module defines base configuration models for connectors, including settings for
connecting to OpenCTI and general connector configurations. It provides a structured way
to manage and validate configuration parameters using Pydantic.
These models can be extended to create specific configurations for different types of connectors.
"""

import os
from abc import ABC
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import __main__
from connectors_sdk.core.pydantic import ListFromString
from connectors_sdk.exceptions import (
    ConfigValidationError,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
    create_model,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_MAIN_PATH = os.path.dirname(os.path.abspath(__main__.__file__))


class _BaseConfigModel(BaseModel, ABC):
    """Base class for global config models
    To prevent attributes from being modified after initialization.
    """

    model_config = ConfigDict(extra="allow", frozen=True, validate_default=True)


class _OpenCTIConfig(_BaseConfigModel):
    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )


class BaseConnectorConfig(_BaseConfigModel, ABC):
    """Base class for connector configuration.

    Attributes:
        id (str): A UUID v4 to identify the connector in OpenCTI.
        name (str): The name of the connector.
        scope (ListFromString): The scope of the connector, e.g. 'flashpoint
        duration_period (timedelta): The period of time to await between two runs of the connector.
        log_level (Literal): The minimum level of logs to display. Options are 'debug',
            'info', 'warn', 'warning', 'error', 'critical'.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'."
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector."
    )
    log_level: Literal["debug", "info", "warn", "warning", "error", "critical"] = Field(
        description="The minimum level of logs to display."
    )


class _SettingsLoader(BaseSettings):
    model_config = SettingsConfigDict(
        frozen=True,
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_MAIN_PATH}/config.yml",
        env_file=f"{_MAIN_PATH}/.env",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customise the sources of settings for the connector.

        This method is called by the Pydantic BaseSettings class to determine the order of sources.
        The configuration come in this order either from:
            1. YAML file
            2. .env file
            3. Environment variables
            4. Default values
        """
        if Path(settings_cls.model_config["yaml_file"] or "").is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        if Path(settings_cls.model_config["env_file"] or "").is_file():  # type: ignore
            return (dotenv_settings,)
        return (env_settings,)


class BaseConnectorSettings(_BaseConfigModel, ABC):
    """Interface class for managing and loading the global configuration for connectors.

    This class centralizes settings related to OpenCTI and the connector,
    with support for YAML files, .env files, and environment variables.

    Attributes:
        opencti (_OpenCTIConfig): Configuration settings for connecting to OpenCTI.
        connector (BaseConnectorConfig): Configuration settings specific to the connector.

    Examples:
        >>> class ConnectorSettings(BaseExternalImportConnectorSettings)
        ...     description: str = Field(
        ...         description="The description of the connector.",
        ...         default="POC Connector for demonstration purposes",
        ...     )
        ...
        >>> class ExampleAPISettings(BaseSettings):
        ...     api_key: str = Field(description="API key for authentication")
        ...
        >>> class ExampleConnectorSettings(BaseConnectorSettings):
        ...     connector: ConnectorSettings = Field(default_factory=ConnectorSettings)
        ...     connector_api: ExampleAPISettings = Field(default_factory=ExampleAPISettings)
        ...
        >>> settings = ExampleConnectorSettings()
        >>> print(settings.opencti.url)
        >>> print(settings.connector.description)
        >>> print(settings.connector_api.api_key)

    Raises:
        connectors_sdk.exceptions.ConfigValidationError: Custom error raised during configuration validation.
    """

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,  # type: ignore[arg-type]
        description="OpenCTI configurations.",
    )
    connector: BaseConnectorConfig = Field(
        default_factory=BaseConnectorConfig,  # type: ignore[arg-type]
        description="Connector configurations.",
    )

    def __init__(self) -> None:
        """Initialize the configuration model and handle validation errors."""
        try:
            super().__init__()
        except ValidationError as e:
            raise ConfigValidationError("Error validating configuration.") from e

    @model_validator(mode="before")
    @classmethod
    def _load_config_dict(cls, _: Any) -> dict[str, Any]:
        # Re-define a SettingsLoader model with fields defined in BaseConnectorSettings
        fields: dict[str, Any] = dict.fromkeys(cls.model_fields.keys(), dict)
        settings_loader = create_model(
            "SettingsLoader",
            __base__=_SettingsLoader,
            **fields,
        )

        # Get config dict to send for validation
        config_dict: dict[str, Any] = settings_loader().model_dump()
        return config_dict

    def model_dump_pycti(self) -> dict[str, Any]:
        """Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`."""
        return self.model_dump(mode="json", context={"mode": "pycti"})


class BaseExternalImportConnectorSettings(BaseConnectorConfig):
    """Settings class for external import connectors.

    Attributes:
        id (str): A UUID v4 to identify the connector in OpenCTI.
        name (str): The name of the connector.
        scope (ListFromString): The scope of the connector, e.g. 'flashpoint'.
        duration_period (timedelta): The period of time to await between two runs of the connector.
        log_level (Literal): The minimum level of logs to display. Options are 'debug',
            'info', 'warn', 'warning', 'error', 'critical'.
        type (str): The type of the connector, set to "EXTERNAL_IMPORT" for external import connectors.
    """

    type: str = "EXTERNAL_IMPORT"


class BaseInternalEnrichmentsConnectorSettings(BaseConnectorConfig):
    """Settings class for internal enrichment connectors.

    Attributes:
        id (str): A UUID v4 to identify the connector in OpenCTI.
        name (str): The name of the connector.
        scope (ListFromString): The scope of the connector, e.g. 'flashpoint'.
        duration_period (timedelta): The period of time to await between two runs of the connector.
        log_level (Literal): The minimum level of logs to display. Options are 'debug',
            'info', 'warn', 'warning', 'error', 'critical'.
        type (str): The type of the connector, set to "INTERNAL_ENRICHMENT" for internal enrichment connectors.
    """

    type: str = "INTERNAL_ENRICHMENT"


class BaseStreamConnectorSettings(BaseConnectorConfig):
    """Settings class for stream connectors.

    Attributes:
        id (str): A UUID v4 to identify the connector in OpenCTI.
        name (str): The name of the connector.
        scope (ListFromString): The scope of the connector, e.g. 'flashpoint'.
        duration_period (timedelta): The period of time to await between two runs of the connector.
        log_level (Literal): The minimum level of logs to display. Options are 'debug',
            'info', 'warn', 'warning', 'error', 'critical'.
        type (str): The type of the connector, set to "STREAM" for stream connectors
    """

    type: str = "STREAM"
