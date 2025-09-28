"""Connector configuration models for OpenCTI and base connector settings."""

from typing import Annotated, Literal

from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field, HttpUrl, PlainSerializer, field_validator

from .base_settings import ConfigBaseSettings

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "warning", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


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
    scope: ListFromString  # Scope can be a list or single value

    type: str = Field(
        default="STREAM",
        description="Should always be set to STREAM for this connector.",
    )
    log_level: LogLevelToLower = Field(
        default="info",
        description="Determines the verbosity of the logs.",
    )
    confidence_level: int = Field(
        default=80,
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

    # Container types configuration
    container_types: ListFromString = Field(
        default=["report", "grouping", "case-incident", "case-rfi", "case-rft"],
        alias="CONNECTOR_CONTAINER_TYPES",
        description="List of container types to process.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_stream(cls, value):
        """Ensure the connector type is always STREAM."""
        return "STREAM"
