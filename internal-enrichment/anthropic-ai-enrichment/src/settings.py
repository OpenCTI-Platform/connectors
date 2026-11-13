from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="2382f232-2b6e-4057-b922-b39c2d325784",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Anthropic AI Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of observables the connector will enrich.",
        default=["Report", "Intrusion-Set", "Threat-Actor-Group", "Malware"],
    )


class AnthropicConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    Anthropic API integration.
    """

    api_key: str = Field(description="Anthropic API key.")
    model: str = Field(
        description="Anthropic model to use for enrichment.",
        default="claude-3-5-haiku-latest",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`
    and `AnthropicConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    anthropic: AnthropicConfig = Field(default_factory=AnthropicConfig)
