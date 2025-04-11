from datetime import date, timedelta
from pathlib import Path
from typing import Annotated, Literal, Optional

from connector.models import FrozenBaseSettings
from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    PositiveInt,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class _ConfigLoaderOCTI(FrozenBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    model_config = SettingsConfigDict(str_strip_whitespace=True, str_min_length=1)

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        ...,
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        ...,
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(FrozenBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    model_config = SettingsConfigDict(str_strip_whitespace=True, str_min_length=1)

    # Config Loader Connector
    id: str = Field(
        ...,
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: Optional[str] = Field(
        default="ServiceNow",
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        default="ServiceNow",
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[Literal["debug", "info", "warn", "error"]] = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        default="PT24H",
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


class _ConfigLoaderServiceNow(FrozenBaseSettings):
    """Interface for loading ServiceNow dedicated configuration."""

    model_config = SettingsConfigDict(str_strip_whitespace=True, str_min_length=1)

    # Config Loader ServiceNow
    instance_name: str = Field(
        ...,
        description="Corresponds to server instance name (will be used for API requests).",
    )
    instance_username: str = Field(
        ...,
        description="This is the name of the user who created the instance.",
    )
    instance_password: str = Field(
        ...,
        description="This is the password of the user who created the instance.",
    )
    import_start_date: date = Field(
        ...,
        description="Start date of first import (ISO date format).",
    )
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        ...,
        description="TLP level to apply on objects imported into OpenCTI.",
    )


class ConfigLoader(FrozenBaseSettings):
    """Interface for loading global configuration settings."""

    model_config = SettingsConfigDict(env_nested_delimiter="_", env_nested_max_split=1)

    opencti: _ConfigLoaderOCTI = Field(..., description="OpenCTI configurations.")
    connector: _ConfigLoaderConnector = Field(
        ..., description="Connector configurations."
    )
    servicenow: _ConfigLoaderServiceNow = Field(
        ..., description="ServiceNow configurations."
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
