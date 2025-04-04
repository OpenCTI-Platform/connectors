import datetime

from pydantic import BaseModel, Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

from shared.opencti_connector_settings.src.enums import ConnectorType, LogLevelType

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
    token: SecretStr
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class _ConnectorConfig(BaseModel):
    id: str  # FIXME: Must be a UUID ?
    name: str
    type: ConnectorType
    scope: list[str]  # FIXME: Should it be an Enum ?
    duration_period: datetime.timedelta

    log_level: LogLevelType = Field(default=LogLevelType.INFO)

    # TODO: Make all variable a pydantic Field
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

    @model_validator(mode="before")
    def set_default_listen_protocol_api_uri(cls, values: dict) -> dict:
        # FIXME: Create a validator that inforce values not to be "ChangeMe" ?
        if (
            "listen_protocol_api_uri" not in values
            and "listen_protocol_api_ssl" in values
        ):
            values["listen_protocol_api_uri"] = "https://127.0.0.1:7070"
        return values


class OpenCTIConnectorSettings(BaseSettings):
    opencti: _OpenCTIConfig
    connector: _ConnectorConfig

    class Config:
        # files needs to be at the same level as the module
        yaml_file = "config.yml"
        env_file = ".env"
        env_nested_delimiter = "_"  # FIXME: Should be "__"
        env_nested_max_split = 1  # FIXME: Must find another way

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
        Define the sources and their order for loading the settings values.
        The order is as follows as the configuration files set must be loaded first
        to avoid confusions with the environment variables.
        """
        return (
            YamlConfigSettingsSource(settings_cls),  # First: fallback YAML file
            dotenv_settings,  # Optional: fallback to .env file
            env_settings,  # Optional: environment variables
        )
