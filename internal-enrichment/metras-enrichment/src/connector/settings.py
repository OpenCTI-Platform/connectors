"""Pydantic settings for the Metras Enrichment connector (INTERNAL_ENRICHMENT)."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="f9d92e7f-3ee4-4a2a-a8e6-8b07766c66ab",
        description="The unique identifier of the connector.",
        examples=["f9d92e7f-3ee4-4a2a-a8e6-8b07766c66ab"],
    )
    name: str = Field(
        default="Metras-Enrichment",
        description="The name of the connector.",
        examples=["Metras-Enrichment"],
    )
    scope: ListFromString = Field(
        default=["IPv4-Addr", "StixFile"],
        description="Entity types this connector enriches.",
        examples=[["IPv4-Addr", "StixFile"]],
    )
    auto: bool = Field(
        default=False,
        description="Automatically enrich entities when they are created.",
        examples=[False],
    )


class MetrasConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://api.metras.sa/api"),
        description="Base URL of the Metras API.",
        examples=["https://api.metras.sa/api"],
    )
    api_key: SecretStr = Field(
        description="Metras API key (X-API-KEY header).",
        examples=["ChangeMe"],
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify TLS certificates.",
        examples=[True],
    )
    max_tlp: TLPLevel = Field(
        default=TLPLevel.AMBER_STRICT,
        description="Maximum TLP level the connector will enrich.",
        examples=["amber+strict"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    metras: MetrasConfig = Field(default_factory=MetrasConfig)
