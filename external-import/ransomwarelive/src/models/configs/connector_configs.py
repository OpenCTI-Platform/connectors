from datetime import timedelta
from typing import Annotated, Literal, Optional

from models.configs import ConfigBaseSettings
from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)

LogLevelToLower = Annotated[
    Literal["debug", "info", "warn", "warning", "error"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


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
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    log_level: Optional[LogLevelToLower] = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        default="PT10M",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )

    @field_validator("type")
    def force_value_for_type_to_be_internal_enrichment(cls, value):
        return "EXTERNAL_IMPORT"
