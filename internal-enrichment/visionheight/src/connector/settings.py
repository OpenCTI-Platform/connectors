from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Connector-level configuration for the VisionHeight internal enrichment connector.
    Overrides the base class to set our defaults for `name` and `scope`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="VisionHeight",
    )
    scope: str = Field(
        description="Comma-separated list of OpenCTI entity types this connector enriches.",
        default="IPv4-Addr,Domain-Name",
    )


class VisionHeightConfig(BaseConfigModel):
    """
    VisionHeight-specific configuration: API credentials, URL, and TLP cap.
    """

    api_base_url: HttpUrl = Field(
        description="VisionHeight API base URL. Override for white-label or staging endpoints.",
        default="https://api.visionheight.com",
    )
    api_key: SecretStr = Field(
        description="VisionHeight API key used to authenticate requests (sent as the x-api-key header).",
    )
    max_tlp_level: Literal[
        "clear",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Maximum TLP level of observables this connector will enrich. Observables marked above this level cause the enrichment to abort with an error logged.",
        default="amber+strict",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Top-level settings combining base connector config with VisionHeight-specific config.
    Loaded by the OpenCTI connector helper at startup.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    visionheight: VisionHeightConfig = Field(default_factory=VisionHeightConfig)
