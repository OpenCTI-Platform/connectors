from datetime import timedelta
from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)
from src.models.configs.base_settings import ConfigBaseSettings

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "warning", "error"],
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
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str
    name: str
    scope: str

    type: Optional[str] = Field(
        default="STREAM",
        description="Should always be set to STREAM for this connector.",
    )
    log_level: Optional[LogLevelToLower] = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    live_stream_id: Optional[str] = Field(
        default="live",
        description="Identifier of the stream to listen.",
    )
    live_stream_listen_delete: bool = Field(
        default=True,
        description="Listen delete events",
    )
    live_stream_no_dependencies: bool = Field(
        default=True,
        description="Listen Stream No dependencies",
    )

    @field_validator("type")
    def force_value_for_type_to_be_stream(cls, value):
        return "STREAM"

