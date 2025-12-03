from typing import Annotated, Literal, Optional

from connectors_sdk.core.pydantic import ListFromString
from models.configs.base_settings import ConfigBaseSettings
from pydantic import Field, HttpUrl, PlainSerializer, field_validator

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
    scope: ListFromString
    duration_period: Optional[str] = Field(
        default="PT24H",
        description="ISO8601 Duration format starting with 'P' for Period (e.g., 'PT24H' for 24 hours).",
    )

    type: str = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    log_level: LogLevelToLower = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"
