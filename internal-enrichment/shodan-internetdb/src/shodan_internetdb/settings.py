"""Pydantic settings for the Shodan InternetDB connector."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field

__all__ = [
    "ConnectorSettings",
]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector section for the Shodan InternetDB connector."""

    name: str = Field(
        description="The name of the connector.",
        default="Shodan InternetDB",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9e52e250-df68-442d-82e2-e4721ddbf0b2",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the observable types it enriches.",
        default=["IPv4-Addr"],
    )


class ShodanConfig(BaseConfigModel):
    """Config fields specific to the Shodan InternetDB connector."""

    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:RED",
        "TLP:CLEAR",
        "TLP:AMBER+STRICT",
    ] = Field(
        description="The maximum TLP marking of observables the connector is allowed to process.",
        default="TLP:WHITE",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL connections to the Shodan InternetDB API.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    shodan: ShodanConfig = Field(default_factory=ShodanConfig)
