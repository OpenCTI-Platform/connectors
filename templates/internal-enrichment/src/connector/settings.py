from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
)
from pydantic import Field, HttpUrl


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

    api_base_url: HttpUrl = Field(description="External API base URL.")
    api_key: str = Field(description="API key for authentication.")


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """
    Override `BaseInternalEnrichmentConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `TemplateConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
