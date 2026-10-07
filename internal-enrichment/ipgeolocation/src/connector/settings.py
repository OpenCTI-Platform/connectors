from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr

TLPLevel = Literal["clear", "white", "green", "amber", "amber+strict", "red"]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector-level settings for the IPGeolocation.io enrichment connector."""

    name: str = Field(
        description="The name of the connector.",
        default="IPGeolocation.io",
    )
    scope: ListFromString = Field(
        description="The observable types the connector enriches.",
        default=["IPv4-Addr", "IPv6-Addr"],
    )
    auto: bool = Field(
        description=(
            "Enrich new observables automatically. Every lookup spends API credits, "
            "so this is off by default."
        ),
        default=False,
    )


class IPGeolocationConfig(BaseConfigModel):
    """Settings specific to IPGeolocation.io."""

    api_key: SecretStr = Field(
        description="IPGeolocation.io API key.",
        min_length=1,
    )
    api_base_url: HttpUrl = Field(
        description="IPGeolocation.io API base URL.",
        default="https://api.ipgeolocation.io",
    )
    timeout: int = Field(
        description="HTTP request timeout in seconds.",
        default=30,
        ge=1,
    )
    include_security: bool = Field(
        description=(
            "Request the security module: threat score and VPN, proxy, Tor, relay, "
            "bot, spam and attacker flags (paid plans, 2 extra credits)."
        ),
        default=True,
    )
    include_abuse: bool = Field(
        description="Request the abuse contact module (paid plans, 1 extra credit).",
        default=True,
    )
    include_hostname: bool = Field(
        description="Request the hostname of the IP address (paid plans, no extra credit).",
        default=True,
    )
    max_tlp_level: TLPLevel = Field(
        description="Highest TLP of the observables the connector sends to IPGeolocation.io.",
        default="amber+strict",
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to the objects the connector creates.",
        default="clear",
    )
    create_labels: bool = Field(
        description="Add labels to the observable, such as `vpn`, `tor` or `risk:high`.",
        default=True,
    )
    create_relationships: bool = Field(
        description="Link the observable to its country, city, autonomous system and organizations.",
        default=True,
    )
    create_indicator: bool = Field(
        description="Create a STIX indicator when the risk score reaches `indicator_threshold`.",
        default=True,
    )
    indicator_threshold: int = Field(
        description="Risk score (0-100) from which an indicator is created.",
        default=50,
        ge=0,
        le=100,
    )
    create_note: bool = Field(
        description="Attach a note with the full enrichment report to the observable.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the IPGeolocation.io connector, read from environment variables or `config.yml`."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    ipgeolocation: IPGeolocationConfig = Field(default_factory=IPGeolocationConfig)
