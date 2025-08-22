import abc
import os
import warnings
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))

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


class ConfigRetrievalError(Exception):
    """Known errors wrapper for config loaders."""


class LogLevelType(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


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
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class ConnectorConfig(BaseModel):
    id: str
    name: str
    type: Literal["EXTERNAL_IMPORT"] = Field(default="EXTERNAL_IMPORT")
    scope: ListFromString
    duration_period: timedelta
    log_level: LogLevelType

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


class BaseConnectorSettings(abc.ABC, BaseSettings):
    opencti: _OpenCTIConfig
    connector: ConnectorConfig

    # files needs to be at the same level as the module
    model_config = SettingsConfigDict(
        env_nested_delimiter="_", env_nested_max_split=1, enable_decoding=False
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


class _ConnectorConfig(ConnectorConfig):
    name: str = Field(
        description="Name of the connector",
        min_length=1,
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        min_length=1,
    )
    log_level: LogLevelType = Field(
        default=LogLevelType.ERROR, description="Determines the verbosity of the logs"
    )
    duration_period: timedelta = Field(
        default=timedelta(minutes=10),
        description="Duration between two scheduled runs of the connector (ISO 8601 format)",
    )

    pull_history: bool = Field(
        default=False, description="Whether to pull historic data"
    )
    history_start_year: int = Field(default=2023, description="The year to start from")
    create_threat_actor: bool = Field(
        default=False, description="Whether to create a Threat Actor object"
    )


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `CONNECTOR_RUN_EVERY` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})

        if run_every := connector_data.pop("run_every", None):
            warnings.warn(
                "Env var 'CONNECTOR_RUN_EVERY' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )
            unit_run_every = run_every[-1:]
            if unit_run_every == "d":
                connector_data["duration_period"] = timedelta(days=int(run_every[:-1]))
            elif unit_run_every == "h":
                connector_data["duration_period"] = timedelta(hours=int(run_every[:-1]))
            elif unit_run_every == "m":
                connector_data["duration_period"] = timedelta(
                    minutes=int(run_every[:-1])
                )
            elif unit_run_every == "s":
                connector_data["duration_period"] = timedelta(
                    seconds=int(run_every[:-1])
                )
            else:
                raise ValueError(f"Invalid value for CONNECTOR_RUN_EVERY: {run_every}")
        return data
