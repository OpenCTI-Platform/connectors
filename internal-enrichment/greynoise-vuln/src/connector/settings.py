from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="52a897dc-d4b0-46b0-8694-bf94a814da4e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="GreyNoise Vulnerability Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["vulnerability"],
    )


class GreyNoiseVulnConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `GreyNoiseVulnConnector`.
    """

    key: SecretStr = Field(
        description="The GreyNoise API key.",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="The maximal TLP of the vulnerability being enriched.",
        default="TLP:AMBER",
    )
    name: str = Field(
        description="The name of the GreyNoise entity (used as the author identity in STIX).",
        default="GreyNoise Internet Scanner",
    )
    description: str = Field(
        description="The description of the GreyNoise entity.",
        default="GreyNoise collects and analyzes opportunistic scan and attack activity for devices connected directly to the Internet.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`
    and `GreyNoiseVulnConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    greynoise_vuln: GreyNoiseVulnConfig = Field(default_factory=GreyNoiseVulnConfig)
