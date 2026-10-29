from __future__ import annotations

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """`EXTERNAL_IMPORT` connector config with Stairwell defaults.

    `duration_period` is the scheduling interval (ISO-8601); the SDK's
    `ExternalImportConnector` runs the import on it.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Stairwell Import",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["stairwell"],
    )
    duration_period: timedelta = Field(
        description="Interval between two runs of the connector (ISO-8601).",
        default=timedelta(days=1),
    )


class StairwellImportConfig(BaseConfigModel):
    """Stairwell-specific configuration (env prefix `STAIRWELL_IMPORT_`)."""

    api_token: SecretStr = Field(description="Stairwell API token (Bearer auth).")
    api_base_url: HttpUrl = Field(
        description="Stairwell API base URL.",
        default="https://app.stairwell.com",
    )
    organization_id: str = Field(
        description="Optional Stairwell organization id (rate-limit header).",
        default="",
    )
    user_id: str = Field(
        description="Optional Stairwell user id (rate-limit header).",
        default="",
    )
    tlp: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = Field(
        description="TLP marking applied to imported entities.",
        default="green",
    )
    first_run_window: str = Field(
        description="ISO-8601 duration to backfill on the first run.",
        default="P1D",
    )
    max_indicators: int = Field(
        description="Maximum indicators emitted per run.",
        default=1000,
    )
    page_size: int = Field(
        description="Stairwell API page size.",
        default=100,
    )
    indicator_validity_days: int = Field(
        description="Days added to valid_from to compute valid_until.",
        default=90,
    )
    min_bucket: str = Field(
        description="Minimum MalEval bucket: LOW, MEDIUM, HIGH, or VERY_HIGH.",
        default="HIGH",
    )
    scope: str = Field(
        description=(
            "Reserved (forward-compat): accepted but not yet effective; every "
            "run currently queries the full corpus regardless of this value."
        ),
        default="environment",
    )
    wrapper: Literal["grouping", "report"] = Field(
        description="Per-run wrapper SDO: 'grouping' or 'report'.",
        default="grouping",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with the external-import + Stairwell blocks."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    stairwell_import: StairwellImportConfig = Field(
        default_factory=StairwellImportConfig
    )
