import abc
import datetime
from pathlib import Path
from typing import Annotated, Literal

from base_connector.enums import LogLevelType
from base_connector.errors import ConfigRetrievalError
from pycti import ConnectorType
from pydantic import (
    BaseModel,
    Field,
    HttpUrl,
    field_serializer,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    NoDecode,
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


class _OpenCTIConfig(BaseModel):
    url: HttpUrl
    token: str
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class _ConnectorConfig(BaseModel):
    id: str
    name: str
    type: ConnectorType
    scope: Annotated[list[str], NoDecode]
    duration_period: datetime.timedelta

    log_level: LogLevelType = Field(default=LogLevelType.ERROR)
    auto: bool = Field(default=False)
    expose_metrics: bool = Field(default=False)
    metrics_port: int = Field(default=9095)
    only_contextual: bool = Field(default=False)
    run_and_terminate: bool = Field(default=False)
    validate_before_import: bool = Field(default=False)
    queue_protocol: str = Field(default="amqp")
    queue_threshold: int = Field(default=500)

    send_to_queue: bool = Field(default=True)
    send_to_directory: bool = Field(default=False)
    send_to_directory_path: str | None = Field(default=None)
    send_to_directory_retention: int = Field(default=7)

    @field_serializer("scope", when_used="json")
    def serialize_scope(self, scope: list[str]) -> str:
        # OpenCTIHelper expects the original format of the scope like "scope1,scope2,scope3"
        return ",".join(scope)

    @field_validator("scope", mode="before")
    @classmethod
    def validate_scope(cls, v: str) -> list[str]:
        # We want to convert the scope from a string to a list of strings
        return v.split(",")


class BaseConnectorConfig(abc.ABC, BaseSettings):
    opencti: _OpenCTIConfig
    connector: _ConnectorConfig

    # files needs to be at the same level as the module
    model_config = SettingsConfigDict(env_nested_delimiter="_", env_nested_max_split=1)

    @property
    @abc.abstractmethod
    def tlp_level(
        self,
    ) -> Literal["white", "clear", "green", "amber", "amber+strict", "red"]:
        raise NotImplementedError("TLP level must be set.")

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
