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
        default="FirstEpss",
    )


class FirstEpssConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `FirstEpssConnector`.
    """

    api_base_url: str = Field(
        description="The base URL of the FIRST EPSS API.",
        default="https://api.first.org/data/v1/epss",
    )
    max_tlp: str = Field(
        description="The maximum TLP level for the connector.",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `FirstEpssConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    first_epss: FirstEpssConfig = Field(default_factory=FirstEpssConfig)
