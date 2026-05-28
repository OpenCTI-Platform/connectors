import abc
import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from base_connector.enums import LogLevelType
from base_connector.errors import ConfigRetrievalError
from pydantic import BaseModel, BeforeValidator, Field, HttpUrl, PlainSerializer
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

"""
All the variables that have default values will override configuration from the OpenCTI helper.

All the variables of this classes are customizable through:
    - config.yml 
    - .env
    - environment variables.

If a variable is set in 2 different places, the first one will be used in this order:
    1. YAML file
    2. .env file
    3. Environment variables
    4. Default value
    
WARNING:
    The Environment variables in the .env or global environment must be set in the following format:
    OPENCTI_<variable>
    CONNECTOR_<variable>
    
    the split is made on the first occurrence of the "_" character.
"""


def environ_list_validator(value: str | list[str]) -> list[str]:
    if isinstance(value, str):
        return [string.strip() for string in value.split(",")]
    return value


def pycti_list_serializer(v: list[str], info: SerializationInfo) -> str | list[str]:
    if isinstance(v, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(v)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
    return v


ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(environ_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]


class _OpenCTIConfig(BaseModel):
    url: HttpUrl
    token: str


class ConnectorConfig(BaseModel):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    type: Literal["EXTERNAL_IMPORT"] = Field(
        default="EXTERNAL_IMPORT",
        description="The type of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
    )
    duration_period: datetime.timedelta = Field(
        description="The period of time to await between two runs of the connector.",
    )
    log_level: LogLevelType = Field(
        description="The minimum level of logs to display.",
    )


class BaseConnectorSettings(abc.ABC, BaseSettings):
    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,
        description="Configuration for the OpenCTI platform.",
    )
    connector: ConnectorConfig = Field(
        default_factory=ConnectorConfig,
        description="Configuration for the connector.",
    )

    # files needs to be at the same level as the module
    model_config = SettingsConfigDict(
        extra="allow",
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
    )

    def __init__(self) -> None:
        try:
            super().__init__()
        except Exception as e:
            raise ConfigRetrievalError("Invalid OpenCTI configuration.", e) from e

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
        return self.model_dump(mode="json", context={"mode": "pycti"})
