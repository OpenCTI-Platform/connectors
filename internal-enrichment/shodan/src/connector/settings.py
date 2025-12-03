from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Shodan",
    )


class ShodanConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ShodanConnector`.
    """

    token: SecretStr = Field(
        description="The token of the Shodan",
    )
    max_tlp: str = Field(
        description="The maximal TLP of the observable being enriched.",
        default="TLP:AMBER",
    )
    default_score: int = Field(
        description="Default_score allows you to add a default score for an indicator and its observable",
        default=50,
    )
    import_search_results: bool = Field(
        description="Returns the results of the search against the enriched indicator (Search the SHODAN database).",
        default=True,
    )
    create_note: bool = Field(
        description="Adds Shodan results to a note, otherwise it is saved in the description.",
        default=True,
    )
    use_isp_name_for_asn: bool = Field(
        description="Use the ISP name for ASN name rather than AS+Number.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `ShodanConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    shodan: ShodanConfig = Field(default_factory=ShodanConfig)
