import datetime
import logging
import os
from pathlib import Path
from typing import Annotated, Literal

from dragos.interfaces.common import FrozenBaseModel
from pycti import ConnectorType
from pydantic import (
    AwareDatetime,
    BaseModel,
    Field,
    HttpUrl,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

logger = logging.getLogger(__name__)

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class ConfigRetrievalError(Exception):
    """Known errors wrapper for config loaders."""


class _OpenCTIConfig(FrozenBaseModel):
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

    log_level: str = Field(default="info")
    auto: bool = Field(default=False)
    expose_metrics: bool = Field(default=False)
    metrics_port: int = Field(default=9095)
    only_contextual: bool = Field(default=False)
    run_and_terminate: bool = Field(default=False)
    validate_before_import: bool = Field(default=False)
    queue_protocol: str = Field(default="amqp")
    queue_threshold: int = Field(default=500)

    listen_protocol: str = Field(default="AMQP")
    listen_protocol_api_port: int = Field(default=7070)
    listen_protocol_api_path: str = Field(default="/api/callback")
    listen_protocol_api_ssl: bool = Field(default=False)
    listen_protocol_api_uri: str = Field(default="http://127.0.0.1:7070")

    send_to_queue: bool = Field(default=False)
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

    @model_validator(mode="before")
    @classmethod
    def set_default_listen_protocol_api_uri(
        cls, values: dict[str, str]
    ) -> dict[str, str]:
        if (
            "listen_protocol_api_uri" not in values
            and "listen_protocol_api_ssl" in values
        ):
            values["listen_protocol_api_uri"] = "https://127.0.0.1:7070"
        return values


class _DragosConfig(FrozenBaseModel):
    api_base_url: HttpUrl = Field(description="Dragos API base URL.")
    api_token: str = Field(description="Dragos API token.")
    import_start_date: AwareDatetime = Field(description="Start date of first import.")
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        description="Traffic Light Protocol (TLP) level of the report."
    )


class Config(BaseSettings):
    connector: _ConnectorConfig
    dragos: _DragosConfig
    opencti: _OpenCTIConfig

    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../config.yml",
        env_file=f"{_FILE_PATH}/../.env",
        env_nested_delimiter="_",
        env_nested_max_split=1,
    )

    def __init__(self) -> None:
        """Initialize the configuration."""
        try:
            super().__init__()
        except ValidationError as exc:
            error_message = "Invalid OpenCTI configuration."
            logger.error(error_message)
            raise ConfigRetrievalError(error_message, exc) from exc

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

        This method is called by the Pydantic BaseSettings class to determine the order of sources
        The configuration come in this order either from:
            1. YAML file
            2. .env file
            3. Environment variables
            4. Default values
        """
        if Path(settings_cls.model_config["yaml_file"]).is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        if Path(settings_cls.model_config["env_file"]).is_file():  # type: ignore
            return (dotenv_settings,)
        return (env_settings,)
