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
    propagate_malware_relationship: bool = Field(
        description=(
            "When ``true``, for every YARA Indicator that matches the enriched "
            "Artifact, the connector follows the indicator's ``indicates`` "
            "relationships to Malware entities and emits an additional "
            "``related-to`` STIX relationship from the Artifact to each of "
            "those Malware entities. Defaults to ``false`` to preserve the "
            "connector's previous behaviour."
        ),
        default=False,
    )
    propagate_labels: bool = Field(
        description=(
            "When ``true``, every OpenCTI label carried by a YARA Indicator "
            "that matches the enriched Artifact is added to the Artifact "
            "(via the ``stix_cyber_observable.add_label`` mutation). Defaults "
            "to ``false`` to preserve the connector's previous behaviour."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    yara: YaraConfig = Field(default_factory=YaraConfig)
