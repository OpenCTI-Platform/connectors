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

    @field_validator("type")
    def force_value_for_type_to_be_internal_enrichment(cls, value):
        return "INTERNAL_ENRICHMENT"
