"""Connector configuration models for OpenCTI and base connector settings."""

from typing import Annotated, Literal

from pydantic import Field, HttpUrl, PlainSerializer, SecretStr

from .base_settings import ConfigBaseSettings

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "warning", "error"],
    PlainSerializer(lambda v: str(v).lower(), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class _ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # Config Loader OpenCTI
    url: HttpUrlToString = Field(
        alias="OPENCTI_URL",
        description="The OpenCTI platform URL.",
    )
    token: SecretStr = Field(
        alias="OPENCTI_TOKEN",
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str = Field(
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        description="Name of the connector.",
    )
    scope: str = Field(
        description="The scope or type of data the connector is processing.",
    )

    type: str = Field(
        default="STREAM",
        description="Should always be set to STREAM for this connector.",
    )
    log_level: LogLevelToLower = Field(
        default="info",
        description="Determines the verbosity of the logs.",
    )
    confidence_level: int = Field(
        default=100,
        ge=0,
        le=100,
        description="The default confidence level for created entities (0-100).",
    )

    # Stream-specific configuration
    live_stream_id: str = Field(
        alias="CONNECTOR_LIVE_STREAM_ID",
        description="The ID of the live stream to listen to.",
    )
    live_stream_listen_delete: bool = Field(
        default=True,
        alias="CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
        description="Listen to delete events in the stream.",
    )
    live_stream_no_dependencies: bool = Field(
        default=False,
        alias="CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
        description="Do not auto-resolve dependencies.",
    )
