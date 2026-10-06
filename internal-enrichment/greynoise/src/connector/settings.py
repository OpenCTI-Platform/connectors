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
        default="7cb4182d-9445-4bce-8493-35e27700bea2",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Greynoise",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr"],
    )


class GreynoiseConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `GreynoiseConnector`.
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
        description="Maximum TLP level for data to be sent to GreyNoise.",
        default="TLP:AMBER",
    )
    sighting_not_seen: bool = Field(
        description="Create sighting with count=0 when IP not seen.",
        default=False,
    )
    no_sightings: bool = Field(
        description="Skip any sighting creations.",
        default=False,
    )
    name: str = Field(
        description="The name of the GreyNoise identity created in OpenCTI.",
        default="GreyNoise Intelligence",
    )
    description: str = Field(
        description="The description of the GreyNoise identity created in OpenCTI.",
        default=(
            "GreyNoise collects and analyzes untargeted, widespread, and "
            "opportunistic scan and attack activity that reaches every server "
            "directly connected to the Internet."
        ),
    )
    indicator_score_malicious: int = Field(
        description="The `x_opencti_score` value to set on indicators classified as malicious.",
        default=75,
    )
    indicator_score_suspicious: int = Field(
        description="The `x_opencti_score` value to set on indicators classified as suspicious.",
        default=50,
    )
    indicator_score_benign: int = Field(
        description="The `x_opencti_score` value to set on indicators classified as benign.",
        default=20,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `GreynoiseConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    greynoise: GreynoiseConfig = Field(default_factory=GreynoiseConfig)
