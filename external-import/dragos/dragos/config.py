import datetime
from pathlib import Path
from typing import Literal

from dragos.interfaces.common import FrozenBaseModel
from pycti import ConnectorType
from pydantic import (
    AwareDatetime,
    Field,
    HttpUrl,
    model_validator,
)
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


class _OpenCTIConfig(FrozenBaseModel):
    url: HttpUrl
    token: str
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class _ConnectorConfig(FrozenBaseModel):
    id: str
    name: str
    type: ConnectorType
    scope: str  # Should be a list but pycti helper consider it as a string
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

    live_stream_id: str | None = Field(default=None)
    live_stream_listen_delete: bool = Field(default=True)
    live_stream_no_dependencies: bool = Field(default=False)
    live_stream_with_inferences: bool = Field(default=False)
    live_stream_recover_iso_date: datetime.datetime | None = Field(default=None)
    live_stream_start_timestamp: datetime.datetime | None = Field(default=None)

    send_to_queue: bool = Field(default=False)
    send_to_directory: bool = Field(default=False)
    send_to_directory_path: str | None = Field(default=None)
    send_to_directory_retention: int = Field(default=7)

    @classmethod
    @model_validator(mode="before")
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
    tlp_level: Literal["clear", "green", "amber", "red"] = Field(
        description="Traffic Light Protocol (TLP) level of the report."
    )


class Config(BaseSettings):
    """Connector configuration class.

    This class is used to load the configuration from either:
    - ../config.yml file
    - ../.env file
    - Environment variables
    """

    connector: _ConnectorConfig
    dragos: _DragosConfig
    opencti: _OpenCTIConfig

    model_config = SettingsConfigDict(
        yaml_file="../config.yml",
        env_file="../.env",
        env_nested_delimiter="_",
        env_nested_max_split=1,
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
