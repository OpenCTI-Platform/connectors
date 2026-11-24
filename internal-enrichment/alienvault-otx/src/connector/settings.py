from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorConfig,
    BaseInternalEnrichmentConnectorSettings,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="0781c790-5d76-4539-b3b5-d8e6e74bc9a2",
    )
    name: str = Field(
        description="The name of the connector.",
        default="AlienVault OTX",
    )
    scope: ListFromString = Field(
        description="The scope of the connector: the entity types it enriches.",
        default=["IPv4-Addr"],
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to AlienVault OTX."
        ),
        default=TLPLevel.AMBER,
    )


class AlienvaultOtxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the AlienVault OTX enrichment connector.
    """

    api_key: SecretStr = Field(
        description="API key of the AlienVault OTX account used to query the OTX DirectConnect API.",
    )
    api_base_url: HttpUrl = Field(
        description="Base URL of the AlienVault OTX API.",
        default=HttpUrl("https://otx.alienvault.com"),
    )


class ConnectorSettings(BaseInternalEnrichmentConnectorSettings):
    """
    Override `BaseInternalEnrichmentConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `AlienvaultOtxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    alienvault_otx: AlienvaultOtxConfig = Field(default_factory=AlienvaultOtxConfig)
