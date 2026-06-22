from typing import Annotated, Literal

from connectors_sdk import ListFromString
from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    field_validator,
)
from src.models.configs import ConfigBaseSettings

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


class _ConfigLoaderOCTING(ConfigBaseSettings):
    """Interface for loading **opencti-ng** dedicated configuration.

    Detached mode: the connector ingests directly into opencti-ng using a JWT
    (no OpenCTI registration / worker). The write tenant is read from the JWT,
    so only ``url`` + ``jwt`` are required.
    """

    url: HttpUrlToString = Field(
        alias="OPENCTI_NG_URL",
        description="The opencti-ng platform URL.",
    )
    jwt: str = Field(
        alias="OPENCTI_NG_JWT",
        description="Long-lived connector JWT (generate with opencti-ng's `connector-jwt` tool).",
    )


class _ConfigLoaderConnector(ConfigBaseSettings):
    """Interface for loading Connector dedicated configuration."""

    # Config Loader Connector
    id: str
    name: str
    scope: ListFromString

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
