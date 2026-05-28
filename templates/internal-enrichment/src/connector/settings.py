from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
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
    max_tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
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
