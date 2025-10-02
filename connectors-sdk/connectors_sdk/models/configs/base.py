import os
from abc import ABC
from datetime import timedelta
from pathlib import Path
from typing import Literal

import __main__
from connectors_sdk.core.pydantic import ListFromString
from connectors_sdk.exceptions import (
    ConfigError,
    ConfigValidationError,
)
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_MAIN_PATH = os.path.dirname(os.path.abspath(__main__.__file__))


class BaseConfigModel(BaseModel, ABC):
    """
    Base class for global config models
    To prevent attributes from being modified after initialization
    """

    model_config = ConfigDict(extra="allow", frozen=True, validate_default=True)


class _SettingLoader(BaseSettings):
    # Setup model config and env vars parsing
    model_config = SettingsConfigDict(
        enable_decoding=False,
        env_nested_delimiter="_",
        env_nested_max_split=1,
        env_file=f"{_MAIN_PATH}/../.env",
        yaml_file=f"{_MAIN_PATH}/../config.yml",
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
        """
        Customise the sources of settings for the connector.
        This method is called by the Pydantic BaseSettings class to determine the order of sources
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


class _OpenCTIConfig(BaseConfigModel):
    """
    Define config specific to OpenCTI
    """

    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )


class BaseConnectorConfig(BaseConfigModel, ABC):
    """
    Define config specific to a connector
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


class BaseConnectorSettings(BaseConfigModel, ABC):
    """
    Interface for loading global configuration settings
    """

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,
        description="OpenCTI configurations.",
    )
    connector: BaseConnectorConfig = Field(
        default_factory=BaseConnectorConfig,
        description="Connector configurations.",
    )

    def __init__(self) -> None:
        """
        Wrap BaseConnectorSettings initialization to raise custom exception in case of error.
        """
        try:
            super().__init__()
        except ValidationError as e:
            raise ConfigValidationError(".", e) from e
        except Exception as e:
            raise ConfigError("Invalid OpenCTI configuration.", e) from e

    def model_dump_pycti(self) -> dict:
        """
        Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`.
        """
        return self.model_dump(mode="json", context={"mode": "pycti"})


class BaseExternalImportConnectorConfig(BaseConnectorConfig):
    type: str = "EXTERNAL_IMPORT"


class BaseInternalEnrichmentsConnectorConfig(BaseConnectorConfig):
    type: str = "INTERNAL_ENRICHMENT"


class BaseStreamConnectorConfig(BaseConnectorConfig):
    type: str = "STREAM"
