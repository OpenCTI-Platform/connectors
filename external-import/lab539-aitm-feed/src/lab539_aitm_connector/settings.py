"""Configuration settings for the Lab539 AiTM Feed connector."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Override BaseExternalImportConnectorConfig with Lab539 AiTM Feed defaults."""

    name: str = Field(
        description="The name of the connector.",
        default="Lab539 AiTM Feed",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )


class AiTMFeedConfig(BaseConfigModel):
    """Configuration specific to the Lab539 AiTM Feed connector."""

    api_key: SecretStr = Field(
        description="Lab539 AiTM Feed API key.",
    )
    api_base_url: str = Field(
        description="Base URL of the Lab539 AiTM Feed API.",
        default="https://aitm.lab539.io/v1.0",
    )
    tlp_level: Literal["white", "green", "amber", "amber+strict", "red"] = Field(
        description="TLP marking level applied to all imported objects.",
        default="amber",
    )
    first_run_lookback_days: int = Field(
        description="Number of days of historical data to import on first run.",
        default=7,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings for the Lab539 AiTM Feed connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    aitm_feed: AiTMFeedConfig = Field(
        default_factory=AiTMFeedConfig,
    )
