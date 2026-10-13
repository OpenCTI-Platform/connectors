"""Pydantic settings for the isMalicious connector (manager-supported mode)."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class IsMaliciousConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector section, with this connector's own defaults."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="848e59be-6d88-400f-a707-2a678c76927f",
    )
    name: str = Field(
        description="The name of the connector.",
        default="isMalicious",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "IPv6-Addr", "Domain-Name"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )


class IsMaliciousConfig(BaseConfigModel):
    """isMalicious API configuration."""

    api_url: str = Field(
        description="The base URL of the isMalicious API.",
        default="https://api.ismalicious.com",
    )
    api_key: SecretStr = Field(
        description="The isMalicious API key.",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP level of the observables to enrich.",
        default="TLP:AMBER",
    )
    enrich_ipv4: bool = Field(
        description="Whether to enrich IPv4 addresses.",
        default=True,
    )
    enrich_ipv6: bool = Field(
        description="Whether to enrich IPv6 addresses.",
        default=True,
    )
    enrich_domain: bool = Field(
        description="Whether to enrich domain names.",
        default=True,
    )
    min_score: int = Field(
        description="Minimum risk score (0-100) required to report a finding.",
        default=0,
        ge=0,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the isMalicious connector."""

    connector: IsMaliciousConnectorConfig = Field(
        default_factory=IsMaliciousConnectorConfig
    )
    ismalicious: IsMaliciousConfig = Field(default_factory=IsMaliciousConfig)
