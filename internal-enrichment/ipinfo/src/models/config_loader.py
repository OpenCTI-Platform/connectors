from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    SecretStr,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from src.models import ConfigBaseSettings

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]
TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]
LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class _ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        alias="OPENCTI_URL",
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        alias="OPENCTI_TOKEN",
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str = Field(
        alias="CONNECTOR_ID",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        alias="CONNECTOR_TYPE",
        default="INTERNAL_ENRICHMENT",
        description="Should always be set to INTERNAL_ENRICHMENT for this connector.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "INTERNAL_ENRICHMENT"

    name: Optional[str] = Field(
        alias="CONNECTOR_NAME",
        default="IPInfo",
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        alias="CONNECTOR_SCOPE",
        default="IPv4-Addr,IPv6-Addr",
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        alias="CONNECTOR_LOG_LEVEL",
        default="error",
        description="Determines the verbosity of the logs.",
    )

    auto: Optional[bool] = Field(
        alias="CONNECTOR_AUTO",
        default=True,
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
    )

    listen_protocol: Optional[str] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL",
        default=None,
        description="Protocol used for listening.",
    )

    listen_protocol_api_port: Optional[int] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_PORT",
        default=None,
        description="Port used for API listening.",
    )

    listen_protocol_api_path: Optional[str] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_PATH",
        default=None,
        description="API path for callback.",
    )

    listen_protocol_api_uri: Optional[str] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_URI",
        default=None,
        description="Full URI for API listening.",
    )

    listen_protocol_api_ssl: Optional[bool] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_SSL",
        default=None,
        description="Enable SSL for API listening.",
    )

    listen_protocol_api_ssl_key: Optional[str] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_SSL_KEY",
        default=None,
        description="SSL key file path.",
    )

    listen_protocol_api_ssl_cert: Optional[str] = Field(
        alias="CONNECTOR_LISTEN_PROTOCOL_API_SSL_CERT",
        default=None,
        description="SSL certificate file path.",
    )


class _ConfigLoaderIPInfo(ConfigBaseSettings):
    """Interface for loading IPInfo dedicated configuration."""

    # Config Loader
    token: SecretStr = Field(
        alias="IPINFO_TOKEN",
        description="API token used to authenticate requests to the IPInfo service.",
    )
    max_tlp: Optional[TLPToLower] = Field(
        alias="IPINFO_MAX_TLP",
        default="amber",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    use_asn_name: Optional[bool] = Field(
        alias="IPINFO_USE_ASN_NAME",
        default=True,
        description="If enabled, uses the ASN name instead of the ASN number in enrichment results.",
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
    ipinfo: _ConfigLoaderIPInfo = Field(
        default_factory=_ConfigLoaderIPInfo,
        description="IPInfo configurations.",
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
        env_path = Path(__file__).parents[1] / ".env"
        yaml_path = Path(__file__).parents[1] / "config.yml"

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
