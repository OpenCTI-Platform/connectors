from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal, Optional

from connector.models import ConfigBaseSettings
from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    PlainValidator,
    PositiveInt,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]
TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainValidator(lambda v: v.lower() if isinstance(v, str) else v),
]
LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainValidator(lambda v: v.lower() if isinstance(v, str) else v),
]


class _ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: str = Field(
        default="Aerospace SPARTA",
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        default='["attack-pattern", "course-of-action", "indicator", "identity"]',
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        default="info",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        default="PT5H",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )
    queue_threshold: Optional[PositiveInt] = Field(
        default=None,
        description="Connector queue max size in Mbytes. Default to 500.",
    )
    run_and_terminate: Optional[bool] = Field(
        default=None,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        default=None,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        default=None,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        default=None,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[PositiveInt] = Field(
        default=None,
        description="Connector send-to-directory retention in days.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"


class _ConfigLoaderSparta(ConfigBaseSettings):
    """Interface for loading Sparta dedicated configuration."""

    base_url: Optional[HttpUrlToString] = Field(
        default="https://sparta.aerospace.org/download/STIX?f=latest",
        description="Base URL of the Aerospace SPARTA dataset.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Interface for loading global configuration settings."""

    opencti: _ConfigLoaderOCTI = Field(
        default_factory=_ConfigLoaderOCTI,
        description="OpenCTI configurations.",
    )
    connector: _ConfigLoaderConnector = Field(
        default_factory=_ConfigLoaderConnector,
        description="Connector configurations.",
    )
    sparta: _ConfigLoaderSparta = Field(
        default_factory=_ConfigLoaderSparta,
        description="Sparta configurations.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
            return (
                EnvSettingsSource(
                    settings_cls,
                    env_ignore_empty=True,
                ),
            )
