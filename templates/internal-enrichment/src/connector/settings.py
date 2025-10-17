from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)


class InternalEnrichmentConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Template Connector",
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
    Override `BaseConnectorSettings` to include `InternalEnrichmentConfig` and `TemplateConfig`.
    """

    connector: InternalEnrichmentConfig = Field(
        default_factory=InternalEnrichmentConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
