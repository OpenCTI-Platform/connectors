from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Configuration specific to the internal enrichment connector."""

    name: str = Field(
        description="The name of the internal enrichment connector.",
        default="Malbeacon",
    )
    id: str = Field(
        description="The unique identifier of the internal enrichment connector.",
        default="e7361ca6-8c71-46fc-9ab6-4837e14af66a",
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=["IPv4-Addr", "IPv6-Addr", "Domain-Name"],
    )


class MalbeaconConfig(BaseConfigModel):
    """Configuration specific to the Malbeacon connector (mirror of the existing variables)."""

    api_key: SecretStr = Field(
        description="The API key used to authenticate against the Malbeacon API.",
    )
    api_base_url: HttpUrl = Field(
        description="The base URL of the Malbeacon API.",
        default=HttpUrl("https://api.malbeacon.com/v1/"),
    )
    indicator_score_level: int = Field(
        description="The score assigned to indicators created by the connector.",
        default=50,
    )
    max_tlp: str = Field(
        description="The maximum TLP marking the connector is allowed to enrich.",
        default="TLP:AMBER",
        enum=[
            "TLP:CLEAR",
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    malbeacon: MalbeaconConfig = Field(default_factory=MalbeaconConfig)
