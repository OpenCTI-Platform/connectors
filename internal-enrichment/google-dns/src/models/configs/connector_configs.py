from datetime import timedelta
from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)
from src.models.configs import ConfigBaseSettings

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
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
    id: str
    name: str
    scope: str

    type: Optional[str] = Field(
        alias="CONNECTOR_TYPE",
        default="INTERNAL_ENRICHMENT",
        description="Should always be set to INTERNAL_ENRICHMENT for this connector.",
    )
    auto: Optional[bool] = Field(
        alias="CONNECTOR_AUTO",
        default=False,
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
    )
    confidence_level: Optional[int] = Field(
        alias="CONNECTOR_CONFIDENCE_LEVEL",
        default=100,
        description="The default confidence level (a number between 1 and 100).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        alias="CONNECTOR_LOG_LEVEL",
        default="error",
        description="Determines the verbosity of the logs.",
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

    @field_validator("type")
    def force_value_for_type_to_be_internal_enrichment(cls, value):
        return "INTERNAL_ENRICHMENT"
