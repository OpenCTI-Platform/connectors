"""Pydantic settings for the Metras Enrichment connector (INTERNAL_ENRICHMENT)."""

from connectors_sdk import (
    TLP,
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="f9d92e7f-3ee4-4a2a-a8e6-8b07766c66ab",
        description="The unique identifier of the connector.",
        examples=["f9d92e7f-3ee4-4a2a-a8e6-8b07766c66ab"],
    )
    name: str = Field(
        default="Metras-Enrichment",
        description="The name of the connector.",
        examples=["Metras-Enrichment"],
    )
    scope: ListFromString = Field(
        default=["IPv4-Addr", "StixFile"],
        description="Entity types this connector enriches.",
        examples=[["IPv4-Addr", "StixFile"]],
    )
    auto: bool = Field(
        default=False,
        description="Automatically enrich entities when they are created.",
        examples=[False],
    )
    max_tlp: TLP = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLP.AMBER_STRICT,
    )


class MetrasConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://api.metras.sa/api"),
        description="Base URL of the Metras API.",
        examples=["https://api.metras.sa/api"],
    )
    api_key: SecretStr = Field(
        description="Metras API key (X-API-KEY header).",
        examples=["ChangeMe"],
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify TLS certificates.",
        examples=[True],
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="Maximum TLP level the connector will enrich.",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    metras: MetrasConfig = Field(default_factory=MetrasConfig)
