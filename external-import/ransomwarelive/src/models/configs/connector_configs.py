from datetime import timedelta
from typing import Annotated, Literal

from connectors_sdk import ListFromString
from models.configs import ConfigBaseSettings
from pydantic import Field, HttpUrl, PlainSerializer, PositiveInt, field_validator

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
    scope: ListFromString

    type: str = Field(
        default="EXTERNAL_IMPORT",
        description="Should always be set to EXTERNAL_IMPORT for this connector.",
    )
    log_level: LogLevelToLower = Field(
        default="error",
        description="Determines the verbosity of the logs.",
    )
    duration_period: timedelta = Field(
        default="PT10M",
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )

    # Connector's custom parameters
    pull_history: bool = Field(
        default=False,
        description=(
            "Whether to pull historic data. It is not recommended to set it "
            "to ``true`` as there will be a large influx of data."
        ),
    )
    history_start_year: PositiveInt = Field(
        default=2023,
        description=(
            "Year (or ``YYYYMM``) to start the historical backfill "
            "from. Accepts the four-digit year shape (``2023``) — "
            "backfill begins on January 1st of that year — or the "
            "six-digit year-month shape (``202306``) — backfill "
            "begins on the first of that month. The ransomware.live "
            "feed only goes back to 2020; values older than 2020 "
            "are clamped to ``2020-01`` at runtime."
        ),
    )

    # Entity-creation flags.
    # ``create_intrusion_set`` and ``create_report`` default to ``True``
    # to preserve the behaviour that existed before PR #5590: the connector
    # always emitted an IntrusionSet and a Report per disclosed victim.
    # ``create_threat_actor`` and ``create_campaign`` default to ``False``
    # because they were not produced before that PR and enabling them by
    # default would cause a surge of new entities on existing deployments.
    # Defaults mirror the README configuration table so docs and runtime agree.
    create_threat_actor: bool = Field(
        default=False,
        description="Whether to create a Threat Actor object.",
    )
    create_intrusion_set: bool = Field(
        default=True,
        description="Whether to create an Intrusion Set object.",
    )
    create_campaign: bool = Field(
        default=False,
        description="Whether to create a Campaign object.",
    )
    create_report: bool = Field(
        default=True,
        description="Whether to create a Report object.",
    )

    # TLP marking applied to every emitted SDO. ``TLP:CLEAR`` is the
    # OpenCTI-specific modern label (rendered via the
    # ``x_opencti_definition='TLP:CLEAR'`` extension in
    # ``ConverterToStix.load_marking_definition``); ``TLP:WHITE`` is
    # the legacy STIX 2.1 equivalent and is kept for backwards
    # compatibility with deployments still using the old name.
    marking_value: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:CLEAR",
        description=(
            "TLP marking attached to every emitted STIX object. "
            "``TLP:CLEAR`` (default) is the OpenCTI-specific modern "
            "label; ``TLP:WHITE`` is the legacy STIX 2.1 equivalent."
        ),
    )
    create_leak_site_domains: bool = Field(
        default=False,
        description="Whether to create DomainName observables for ransomware group leak sites and link them to the IntrusionSet",
    )
    create_leak_post_refs: bool = Field(
        default=False,
        description="Whether to include the leak post URL as an external reference on victim reports",
    )

    @field_validator("type")
    def force_value_for_type_to_be_external_import(cls, value):
        return "EXTERNAL_IMPORT"
