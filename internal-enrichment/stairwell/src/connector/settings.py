from __future__ import annotations

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, HttpUrl


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """`INTERNAL_ENRICHMENT` connector config with Stairwell defaults.

    `type`, `id`, `scope`, `auto`, and `log_level` are inherited from
    `BaseInternalEnrichmentConnectorConfig`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Stairwell",
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
    default_tlp: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to entities created by enrichment.",
            default="amber",
        )
    )
    max_tlp_level: Literal[
        "clear", "white", "green", "amber", "amber+strict", "red"
    ] = Field(
        description="Max TLP of an observable the connector is allowed to enrich.",
        default="red",
    )
    variant_limit: int = Field(
        description="Max variant SCOs per file enrichment (0 disables).",
        default=25,
    )
    resolutions_limit: int = Field(
        description="Max DNS resolution rows per domain (0 disables).",
        default=50,
    )
    sightings_limit: int = Field(
        description="Max unique assets per file (0 disables sightings).",
        default=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with the enrichment + Stairwell blocks."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    stairwell: StairwellConfig = Field(default_factory=StairwellConfig)
