from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(
    BaseExternalImportConnectorConfig
):  # pylint: disable=too-few-public-methods
    name: str = Field(default="Spur")
    duration_period: timedelta = Field(
        description="Interval between feed runs (ISO-8601).",
        default=timedelta(hours=24),
    )


class SpurConfig(BaseConfigModel):  # pylint: disable=too-few-public-methods
    api_key: SecretStr = Field(description="Spur API token.")
    feed_urls: ListFromString = Field(
        description="Comma-separated list of Spur feed URLs to download.",
        default=[
            "https://feeds.spur.us/v2/anonymous/feed.json.gz",
            "https://feeds.spur.us/v2/residential/feed.json.gz",
        ],
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to all imported objects.",
            default="amber",
        )
    )
    create_indicators: bool = Field(
        description="Create STIX Indicators for flagged IPs.",
        default=True,
    )
    create_asns: bool = Field(
        description="Create AutonomousSystem objects and belongs-to relationships.",
        default=True,
    )
    create_locations: bool = Field(
        description="Create Location objects and located-at relationships.",
        default=True,
    )
    default_score: int = Field(
        description="Base OpenCTI score for Spur observables (0-100).",
        default=70,
        ge=0,
        le=100,
    )
    batch_size: int = Field(
        description="Number of IP records per STIX bundle sent to OpenCTI.",
        default=5000,
        ge=100,
    )


class ConnectorSettings(
    BaseConnectorSettings
):  # pylint: disable=too-few-public-methods
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    spur: SpurConfig = Field(default_factory=SpurConfig)
