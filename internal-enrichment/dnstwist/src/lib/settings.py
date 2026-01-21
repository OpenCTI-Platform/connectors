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
        default="9ff0437e-dfeb-4340-98c5-3d88d5e1c31e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Dnstwist",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class DnstwistConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DnstwistConnector`.
    """

    fetch_registered: bool = Field(
        description="Only return domains that are actually registered.",
        default=True,
    )
    dns_twist_threads: int = Field(
        description="Number of threads for DNS lookups.",
        default=20,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DnstwistConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    dnstwist: DnstwistConfig = Field(default_factory=DnstwistConfig)
