from __future__ import annotations

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """`INTERNAL_ENRICHMENT` connector config with Stairwell defaults.

    `type`, `id`, `auto`, `log_level`, and `max_tlp` are inherited from
    `BaseInternalEnrichmentConnectorConfig`. `max_tlp` (default amber) is
    the highest TLP an observable may carry and still be sent to Stairwell.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Stairwell",
    )
    scope: ListFromString = Field(
        description="The observable types the connector enriches.",
        default=[
            "StixFile",
            "Domain-Name",
            "IPv4-Addr",
            "IPv6-Addr",
            "Autonomous-System",
        ],
    )


class StairwellConfig(BaseConfigModel):
    """Stairwell-specific configuration (env prefix `STAIRWELL_`)."""

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
    default_tlp: TLPLevel = Field(
        description="TLP marking applied to entities created by enrichment.",
        default=TLPLevel.AMBER,
    )
    variant_limit: int = Field(
        description="Max variant SCOs per file enrichment (0 disables).",
        default=25,
        ge=0,
    )
    resolutions_limit: int = Field(
        description="Max DNS resolution rows per domain (0 disables).",
        default=50,
        ge=0,
    )
    # Sightings carry customer asset names, environment ids, and file paths
    # (which often contain usernames) into OpenCTI, so they are opt-in.
    sightings_limit: int = Field(
        description=(
            "Max unique assets per file; 0 (the default) disables sightings. "
            "Enabling writes asset names, environment ids, and file paths "
            "into OpenCTI."
        ),
        default=0,
        ge=0,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with the enrichment + Stairwell blocks."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    stairwell: StairwellConfig = Field(default_factory=StairwellConfig)
