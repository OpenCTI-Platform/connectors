from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


class IOCExtractorConfig(BaseConfigModel):
    extract_hashes: bool = Field(
        description="Extract file hashes (MD5, SHA-1, SHA-256).",
        default=True,
    )
    extract_ipv4: bool = Field(
        description="Extract IPv4 addresses.",
        default=True,
    )
    extract_ipv6: bool = Field(
        description="Extract IPv6 addresses.",
        default=True,
    )
    extract_domains: bool = Field(
        description="Extract domain names.",
        default=True,
    )
    extract_urls: bool = Field(
        description="Extract URLs.",
        default=True,
    )
    skip_private_ips: bool = Field(
        description="Skip private/reserved IP addresses (RFC 1918, loopback, etc.).",
        default=True,
    )


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="IOC Extractor",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Report"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    ioc_extractor: IOCExtractorConfig = Field(default_factory=IOCExtractorConfig)
