from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


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
        default=[],
    )


class GreynoiseConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `GreynoiseConnector`.
    """

    key: str = Field(
        description="The GreyNoise API key.",
    )
    max_tlp: str = Field(
        description="Maximum TLP level for data to be sent to GreyNoise.",
    )
    sighting_not_seen: bool = Field(
        description="Create sighting with count=0 when IP not seen.",
    )
    no_sightings: bool = Field(
        description="Skip any sighting creations.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `GreynoiseConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    greynoise: GreynoiseConfig = Field(default_factory=GreynoiseConfig)
