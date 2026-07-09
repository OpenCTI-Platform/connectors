from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field

# TLP levels accepted by `OpenCTIConnectorHelper.check_max_tlp`.
# The Vulners SDK does not ship a dedicated TLPLevel enum, so we mirror the
# canonical pycti TLP marking names here.
TLPLevel = Literal[
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override `BaseInternalEnrichmentConnectorConfig` with Vulners defaults
    for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Vulners",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Vulnerability"],
    )


class VulnersConfig(BaseConfigModel):
    """
    Configuration specific to the Vulners enrichment connector.

    Environment variables (handled by connectors-sdk env mapping):
        VULNERS_API_KEY        -> api_key (required)
        VULNERS_API_BASE_URL   -> api_base_url
        VULNERS_MAX_TLP_LEVEL  -> max_tlp_level
    """

    api_key: str = Field(
        description="Vulners API key. Get one at https://vulners.com",
    )
    api_base_url: str = Field(
        description="Vulners API base URL.",
        default="https://vulners.com",
    )
    max_tlp_level: TLPLevel = Field(
        description="Maximum TLP level of the entities the connector is allowed to enrich.",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include the internal-enrichment connector
    configuration and the Vulners-specific configuration.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    vulners: VulnersConfig = Field(default_factory=VulnersConfig)
