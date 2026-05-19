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
        description="The ID of the connector.",
        default="82b58916-a654-4cd4-81de-700eb72a5c94",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Shodan",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ipv4-addr", "indicator"],
    )


class ShodanConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ShodanConnector`.
    """

    token: SecretStr = Field(
        description="Shodan API Key",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
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
