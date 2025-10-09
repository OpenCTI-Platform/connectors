import abc
import os
from pathlib import Path
from typing import Any, Literal

import __main__
from connectors_sdk.core.pydantic import ListFromString
from connectors_sdk.exceptions.error import ConfigError
from pydantic import BaseModel, ConfigDict, Field, HttpUrl
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_MAIN_PATH = os.path.dirname(os.path.abspath(__main__.__file__))


class BaseConfigModel(BaseModel, abc.ABC):
    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        validate_default=True,
    )


class _OpenCTIConfig(BaseConfigModel):
    url: HttpUrl = Field(
        description="The base URL of the OpenCTI instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenCTI.",
    )


class _ConnectorConfig(BaseConfigModel):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
    )
    log_level: Literal["debug", "info", "warning", "error"] = Field(
        description="The minimum level of logs to display."
    )


class BaseInternalEnrichmentsConnectorConfig(_ConnectorConfig, abc.ABC):
    type: Literal["INTERNAL_ENRICHMENT"] = "INTERNAL_ENRICHMENT"

    auto: bool = Field(
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
    )


class BaseConnectorSettings(BaseConfigModel, BaseSettings, abc.ABC):
    model_config = SettingsConfigDict(
        enable_decoding=False,
        env_nested_delimiter="_",
        env_nested_max_split=1,
        yaml_file=f"{_MAIN_PATH}/../config.yml",
        env_file=f"{_MAIN_PATH}/../.env",
    )

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,
        description="OpenCTI configurations.",
    )
    connector: _ConnectorConfig = Field(
        default_factory=_ConnectorConfig,
        description="Connector configurations.",
    )

    def __init__(self) -> None:
        """
        Wrap BaseConnectorSettings initialization to raise custom exception in case of error.
        """
        try:
            super().__init__()
        except Exception as e:
            raise ConfigError("Invalid OpenCTI configuration.", e) from e

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

    def model_dump_pycti(self) -> dict[str, Any]:
        """
        Convert model into a valid dict for `pycti.OpenCTIConnectorHelper`.
        """
        return self.model_dump(mode="json", context={"mode": "pycti"})
