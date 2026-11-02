from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9aae46c5-9e5a-4379-9f1b-49202674de3f",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Bitdefender",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Bitdefender"],
    )
    duration_period: timedelta = Field(
        description="The time to await between next run.",
        default=timedelta(hours=1),
    )


class BitdefenderConfig(BaseConfigModel):
    api_key: SecretStr = Field(
        description="Bitdefender Threat Intelligence API key.",
    )

    http_timeout_seconds: int = Field(
        description="HTTP timeout in seconds for requesting feeds.",
        default=600,
    )

    verify_tls: bool = Field(
        description="Whether to verify the TLS certificate when downloading the feeds.",
        default=True,
    )

    feeds: ListFromString = Field(
        description="Comma-separated list of feeds to download and import."
    )

    min_confidence: int = Field(
        description="Minimum confidence value for the feed entry to be imported (1-99).",
        default=75,
        ge=1,
        le=99,
    )

    min_severity: int = Field(
        description="Minimum severity value for the feed entry to be imported (1-99).",
        default=1,
        ge=1,
        le=99,
    )

    exclude_related_indicators: bool = Field(
        description="Whether to exclude related indicators from import.",
        default=False,
    )

    exclude_similar_files: bool = Field(
        description="Whether to exclude similar files indicators from import (only for file feed).",
        default=False,
    )

    include_suspicious: Literal["true", "false", "only"] = Field(
        description="Whether to import suspicious entries from a file feed (true - yes, false - no, only - only suspicious).",
        default="false",
    )

    include_revoked: Literal["true", "false", "only"] = Field(
        description="Whether to import revoked indicators (true - import, false - do not import, only - import only revoked).",
        default="false",
    )

    detection: bool = Field(
        description="Value to pass for x_opencti_detection value.", default=False
    )

    create_malware_objects: bool = Field(
        description="Create Malware object for each malware indicator (True) or only for malware families (False).",
        default=True,
    )

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if secret in {"", "ChangeMe"}:
            raise ValueError("You must configure valid API key value.")
        return value

    @field_validator("feeds")
    @classmethod
    def validate_feeds(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("At least one feed must be configured.")

        ValidFeeds = ("file", "ip", "web")
        unknown = [feeds for feeds in value if feeds not in ValidFeeds]
        if unknown:
            raise ValueError(
                f"Unknown feeds value {unknown}. Available values: {', '.join(ValidFeeds)}."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    bitdefender: BitdefenderConfig = Field(default_factory=BitdefenderConfig)
