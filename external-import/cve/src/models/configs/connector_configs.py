from datetime import timedelta
from typing import Annotated, Literal, Optional

from pydantic import (
    Field,
    HttpUrl,
    PlainSerializer,
    PositiveInt,
    field_validator,
)
from src.models.configs import ConfigBaseSettings

TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]
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
    id: Optional[str] = Field(
        alias="CONNECTOR_ID",
        default=None,
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    type: Optional[str] = Field(
        alias="CONNECTOR_TYPE",
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    name: Optional[str] = Field(
        alias="CONNECTOR_NAME",
        default=None,
        description="Name of the connector.",
    )
    scope: Optional[str] = Field(
        alias="CONNECTOR_SCOPE",
        default=None,
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    log_level: Optional[LogLevelToLower] = Field(
        alias="CONNECTOR_LOG_LEVEL",
        default="error",
        description="Determines the verbosity of the logs.",
    )
    duration_period: Optional[timedelta] = Field(
        alias="CONNECTOR_DURATION_PERIOD",
        default="PT24H",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )
    queue_threshold: Optional[PositiveInt] = Field(
        alias="CONNECTOR_QUEUE_THRESHOLD",
        default=None,
        description="Connector queue max size in Mbytes. Default to 500.",
    )
    run_and_terminate: Optional[bool] = Field(
        alias="CONNECTOR_RUN_AND_TERMINATE",
        default=None,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        alias="CONNECTOR_SEND_TO_QUEUE",
        default=None,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY",
        default=None,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY_PATH",
        default=None,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[PositiveInt] = Field(
        alias="CONNECTOR_SEND_TO_DIRECTORY_RETENTION",
        default=None,
        description="Connector send-to-directory retention in days.",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"
