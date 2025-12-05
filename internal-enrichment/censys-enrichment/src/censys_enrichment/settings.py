from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field, SecretStr


class _ConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Censys Enrichment",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["IPv4-Addr", "IPv6-Addr", "X509-Certificate"],
        description="The scope of the connector.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )


class _CensysEnrichmentConfig(BaseConfigModel):
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
        description="The maximum TLP level allowed for enrichment.",
    )

    organisation_id: SecretStr = Field(
        description="Censys organisation ID.",
    )
    token: SecretStr = Field(
        description="Censys API token.",
    )


class ConfigLoader(BaseConnectorSettings):
    connector: _ConnectorConfig = Field(
        default_factory=_ConnectorConfig,
        description="Internal Enrichment Connector configurations.",
    )
    censys_enrichment: _CensysEnrichmentConfig = Field(
        default_factory=_CensysEnrichmentConfig,
        description="Censys Enrichment configurations.",
    )
