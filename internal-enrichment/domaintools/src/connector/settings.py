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

    name: str = Field(
        description="The name of the connector.",
        default="Domaintools",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Domain-Name", "Ipv4-Addr"],
    )


class DomaintoolsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DomaintoolsConnector`.
    """

    api_username: str = Field(
        description="The username required for the authentication on DomainTools API.",
    )
    api_key: SecretStr = Field(
        description="The password required for the authentication on DomainTools API.",
    )
    max_tlp: str = Field(
        description="The maximal TLP of the observable being enriched.",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DomaintoolsConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    domaintools: DomaintoolsConfig = Field(default_factory=DomaintoolsConfig)
