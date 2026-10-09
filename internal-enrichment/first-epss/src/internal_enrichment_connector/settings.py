from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="The ID of the connector.",
        default="18f1a9e6-a82b-4ef4-9699-ae406fe4a1a6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="First EPSS",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["vulnerability"],
    )


class FirstEpssConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `FirstEpssConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="The base URL of the FIRST EPSS API.",
        default=HttpUrl("https://api.first.org/data/v1/epss"),
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The maximum TLP level for the connector.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `FirstEpssConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    first_epss: FirstEpssConfig = Field(default_factory=FirstEpssConfig)
