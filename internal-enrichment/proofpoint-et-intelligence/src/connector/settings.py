from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="f2de8084-47ab-4ff2-ae63-e5a7c6e5c720",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ProofPoint ET Intelligence",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "Domain-Name", "StixFile"],
    )
    auto: bool = Field(
        description="Enable/disable auto-enrichment of observables.",
        default=True,
    )


class ProofpointEtIntelligenceConfig(BaseConfigModel):
    """Config fields specific to ProofPoint ET Intelligence connector."""

    api_base_url: HttpUrl = Field(
        description="The base URL of the ProofPoint ET Intelligence API.",
        default=HttpUrl("https://api.emergingthreats.net/v1/"),
    )
    api_key: SecretStr = Field(
        description="The API key used for authentication to ProofPoint ET Intelligence.",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP level the connector is authorized to enrich. "
        "Available values: TLP:CLEAR, TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED.",
        default="TLP:AMBER+STRICT",
    )
    import_last_seen_time_window: timedelta = Field(
        description="The time window for importing 'last_seen' data, specified in ISO 8601 duration format.",
        default=timedelta(days=30),
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    proofpoint_et_intelligence: ProofpointEtIntelligenceConfig = Field(
        default_factory=ProofpointEtIntelligenceConfig
    )
