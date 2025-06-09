import abc
from pathlib import Path
from typing import Annotated, Any, Literal

from base_connector.enums import LogLevelType
from base_connector.errors import ConfigRetrievalError
from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
    model_validator,
)
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
    json_logging: bool = Field(default=True)
    ssl_verify: bool = Field(default=False)


class StreamConnectorConfig(BaseModel):
    id: str
    name: str
    type: Literal["STREAM"] = Field(default="STREAM")
    scope: ListFromString
    log_level: LogLevelType

    live_stream_id: str
    live_stream_listen_delete: bool = Field(default=True)
    live_stream_no_dependencies: bool = Field(default=True)
    live_stream_with_inferences: bool = Field(default=False)
    live_stream_recover_iso_date: str | None = Field(default=None)
    live_stream_start_timestamp: str | None = Field(default=None)

    listen_protocol: str = Field(default="AMQP")
    listen_protocol_uri: str = Field(default="http://127.0.0.1:7070")
    listen_protocol_path: str = Field(default="/api/callback")
    listen_protocol_ssl: bool = Field(default=False)
    listen_protocol_port: int = Field(default=7070)

    # TODO: See what is specific to stream / external
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

    @field_validator("live_stream_id")
    @classmethod
    def validate_live_stream_id(cls, v: str) -> str:
        if v == "changeMe":
            raise ValueError('name cannot be the placeholder "changeMe"')
        return v


class BaseConnectorSettings(abc.ABC, BaseSettings):
    opencti: _OpenCTIConfig
    connector: StreamConnectorConfig

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
