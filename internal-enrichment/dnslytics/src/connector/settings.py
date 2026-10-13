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
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="0bf1d94c-f64c-4b96-8f6d-84f0b5ea34b4",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DNSlytics",
        examples=["DNSlytics"],
    )
    scope: ListFromString = Field(
        description="The entity types the connector enriches. Only Indicators with pattern type `dnslytics` are processed.",
        default=["Indicator"],
        examples=["Indicator"],
    )


class DnslyticsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DnslyticsConnector`.
    """

    api_key: SecretStr = Field(
        description="DNSlytics API key (premium credits). Sent as the `apikey` query parameter, never logged.",
        examples=["0123456789abcdef0123456789abcdef"],
    )
    api_base_url: HttpUrl = Field(
        description=(
            "Base URL of the DNSlytics premium API. Only change it to point the connector "
            "at a local mock server for tests that must not spend credits."
        ),
        default=HttpUrl("https://api.dnslytics.net"),
        examples=["https://api.dnslytics.net", "http://localhost:8000"],
    )
    resolve_hosting: bool = Field(
        description=(
            "Resolve each active domain (DNS A/AAAA), look up the AS of each IP (IP2ASN, free) "
            "and set a `provider:<AS name>` label. If false, only domains and the "
            "`dnslytics:active` / `dnslytics:dropped` label are created."
        ),
        default=True,
        examples=[True, False],
    )
    max_tlp_level: TLPLevel = Field(
        description="Do not enrich Indicators marked above this TLP level.",
        default="green",
        examples=["green", "amber"],
    )
    output_tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object created by the connector.",
        default="clear",
        examples=["clear", "green"],
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DnslyticsConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    dnslytics: DnslyticsConfig = Field(default_factory=DnslyticsConfig)
