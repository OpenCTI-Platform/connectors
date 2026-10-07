"""Pydantic settings for the Shodan InternetDB connector."""

from connectors_sdk import (
    TLP,
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
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
    max_tlp: TLP = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLP.WHITE,
    )


class ShodanConfig(BaseConfigModel):
    """Config fields specific to the Shodan InternetDB connector."""

    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The maximum TLP marking of observables the connector is allowed to process.",
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
