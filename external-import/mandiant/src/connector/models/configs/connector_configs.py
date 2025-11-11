from datetime import timedelta
from typing import Annotated, Literal

from connector.models.configs import ConfigBaseSettings
from connectors_sdk.core.pydantic import ListFromString
from pydantic import (
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "warning", "error"],
    BeforeValidator(lambda v: v.lower() if isinstance(v, str) else v),
    PlainSerializer(lambda v: v.lower(), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class ConfigLoaderOCTI(ConfigBaseSettings):
    """Interface for loading OpenCTI dedicated configuration."""

    # ConfigLoader OpenCTI
    url: HttpUrlToString = Field(
        description="The OpenCTI platform URL.",
    )
    token: str = Field(
        description="The token of the user who represents the connector in the OpenCTI platform.",
    )


class ConfigLoaderConnectorExtra(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # ConfigLoader Connector
    id: str
    name: str
    scope: ListFromString

    type: str = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    log_level: LogLevelToLower = Field(
        default="error",
        description="Determines the verbosity of the logs. Options are debug, info, warn, warning or error.",
    )
    duration_period: timedelta = Field(
        default="PT5M",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"
