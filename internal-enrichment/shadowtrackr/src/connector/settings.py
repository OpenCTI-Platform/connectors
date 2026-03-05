from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ShadowTrackr",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'IPv4-Addr,IPv6-Addr,Indicator'.",
        default=["IPv4-Addr", "IPv6-Addr", "Indicator"],
    )


class ShadowTrackrConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ShadowTrackrConnector`.
    """

    base_url: HttpUrl = Field(
        description="Base URL of the ShadowTrackr API.",
        default="https://shadowtrackr.com/api/v3",
    )
    api_key: SecretStr = Field(description="API key for authentication.")
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Max TLP level of the entities to enrich.",
        default="TLP:AMBER",
    )
    replace_with_lower_score: bool = Field(
        description="Replace the score with a lower score based on the ShadowTrackr false positive estimate.",
        default=False,
    )
    replace_valid_to_date: bool = Field(
        description="Set the valid to date to tomorrow for CDNs, Clouds and VPNs.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `ShadowTrackrConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    shadowtrackr: ShadowTrackrConfig = Field(default_factory=ShadowTrackrConfig)
