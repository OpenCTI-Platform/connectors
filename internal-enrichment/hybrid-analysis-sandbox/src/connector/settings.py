from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="22538379-7caa-41ac-a401-c752db2cd2ac",
    )
    name: str = Field(
        description="The name of the connector.",
        default="HybridAnalysisSandbox",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class HybridAnalysisSandboxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `HybridAnalysisSandboxConnector`.
    """

    api_key: SecretStr = Field(
        description="Hybrid Analysis API token.",
    )
    environment_id: int = Field(
        description="Analysis environment ID (default: 110).",
        default=110,
    )
    max_tlp: str = Field(
        description="Maximum TLP for submission.",
        default="TLP:AMBER",
    )
    token: SecretStr = Field(
        description="Deprecated/unused setting. Use `api_key` (HYBRID_ANALYSIS_TOKEN) instead.",
        deprecated=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `HybridAnalysisSandboxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    hybrid_analysis: HybridAnalysisSandboxConfig = Field(
        default_factory=HybridAnalysisSandboxConfig
    )
