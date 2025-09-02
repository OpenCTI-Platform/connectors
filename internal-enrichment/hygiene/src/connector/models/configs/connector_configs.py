from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)
from src.connector.models.configs import ConfigBaseSettings

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
        default="INTERNAL_ENRICHMENT",
        description="Should always be set to INTERNAL_ENRICHMENT for this connector.",
    )

    log_level: Optional[LogLevelToLower] = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    auto: Optional[bool] = Field(
        default=True,
        description="Enables or disables automatic enrichment of observables for OpenCTI.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_internal_enrichment(cls, value):
        return "INTERNAL_ENRICHMENT"
