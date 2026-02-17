from __future__ import annotations

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Common configuration for connectors of type `EXTERNAL_IMPORT`."""

    name: str = Field(
        description="The name of the connector.",
        default="Checkfirst Import Connector",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(weeks=1),
    )


class CheckfirstConfig(BaseConfigModel):
    """Connector-specific configuration."""

    # API configuration
    api_url: str = Field(
        description="Base URL for the API endpoint (e.g., https://api.example.com).",
    )

    @field_validator("api_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    api_key: str = Field(
        description="API key for authentication (sent in Api-Key header).",
    )
    api_endpoint: str = Field(
        description="API endpoint path (e.g., /v1/articles).",
        default="/v1/articles",
    )

    since: str = Field(
        description="Only ingest articles published on or after this date (ISO 8601).",
        default="2025-01-01T00:00:00Z",
    )
    force_reprocess: bool = Field(
        description=(
            "If true, ignore any saved connector state and start from page 1. "
            "Useful for debugging or re-importing all data."
        ),
        default=False,
    )

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="TLP marking level applied to created STIX entities.",
        default="clear",
    )

    # Resource guards (optional)
    max_row_bytes: int | None = Field(
        description="Skip any API row larger than this approximate number of bytes.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings model loaded from env vars / config.yml."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    checkfirst: CheckfirstConfig = Field(default_factory=CheckfirstConfig)
