from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="TemplateConnector",
    )


class TemplateConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TemplateConnector`.
    """

    api_base_url: str = Field(description="External API base URL.")
    api_key: str = Field(description="API key for authentication.")
    max_tlp_level: str = Field(
        description="Max TLP level of the entities to enrich.",
        default="amber+strict",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `TemplateConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
