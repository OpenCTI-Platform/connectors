from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="840210d2-cb25-4841-81c2-850b431918ee",
    )
    name: str = Field(
        description="The name of the connector.",
        default="YARA",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Artifact"],
    )


class YaraConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `YaraConnector`.
    """

    tlp_level: TLPLevel | None = Field(
        description="Default TLP marking to apply to created relationships when neither the artifact nor the indicator have markings.",
        default=TLPLevel.CLEAR,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    yara: YaraConfig = Field(default_factory=YaraConfig)
