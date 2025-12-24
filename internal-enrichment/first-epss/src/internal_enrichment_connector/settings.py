from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
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
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
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
