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
        default="28672acc-1c40-44d8-8c75-a35a176128d4",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TeamCymruScoutSearch",
    )

    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
        ],
    )


class TeamCymruScoutConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TeamCymruScoutSearchConnector`.
    """

    api_url: str = Field(
        description="Base URL of the Scout API",
        default="https://taxii.cymru.com/api/scout",
    )
    api_token: SecretStr = Field(description="Bearer token for the Scout API")
    max_tlp: str = Field(
        description="Max TLP level for enrichment (default: TLP:AMBER)",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `TeamCymruScoutSearchConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    pure_signal_scout: TeamCymruScoutConfig = Field(
        default_factory=TeamCymruScoutConfig
    )
