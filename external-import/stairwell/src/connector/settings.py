from __future__ import annotations

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """`EXTERNAL_IMPORT` connector config with Stairwell defaults.

    `duration_period` is the scheduling interval (ISO-8601). It replaces the
    previous `STAIRWELL_IMPORT_INTERVAL` env var — scheduling is now owned by
    the OpenCTI connector helper (`schedule_process`).
    """

    name: str = Field(
        description="The name of the connector.",
        default="Stairwell Import",
    )
    duration_period: timedelta = Field(
        description="Interval between two runs of the connector (ISO-8601).",
        default=timedelta(days=1),
    )


class StairwellConfig(BaseConfigModel):
    """Stairwell-specific configuration (env prefix `STAIRWELL_`)."""

    api_token: str = Field(description="Stairwell API token (Bearer auth).")
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
    import_tlp: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to imported entities.",
            default="green",
        )
    )
    import_first_run_window: str = Field(
        description="ISO-8601 duration to backfill on the first run.",
        default="P1D",
    )
    import_max_indicators: int = Field(
        description="Maximum indicators emitted per run.",
        default=1000,
    )
    import_page_size: int = Field(
        description="Stairwell API page size.",
        default=100,
    )
    import_indicator_validity_days: int = Field(
        description="Days added to valid_from to compute valid_until.",
        default=90,
    )
    import_min_bucket: str = Field(
        description="Minimum MalEval bucket: LOW | MEDIUM | HIGH | MALICIOUS.",
        default="HIGH",
    )
    import_scope: str = Field(
        description="Corpus scope: 'environment' (your tenant) or 'global'.",
        default="environment",
    )
    import_wrapper: str = Field(
        description="Per-run wrapper SDO: 'grouping' or 'report'.",
        default="grouping",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with the external-import + Stairwell blocks."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    stairwell: StairwellConfig = Field(default_factory=StairwellConfig)
