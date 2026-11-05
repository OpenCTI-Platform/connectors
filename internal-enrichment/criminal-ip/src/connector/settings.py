from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class CriminalIPConfig(BaseConfigModel):
    token: SecretStr = Field(
        description="Criminal IP API key.",
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="Max TLP level of entities to enrich.",
    )


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(
        description="The name of the connector",
        default="Criminal IP",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["IPv4-Addr", "Domain-Name"],
    )


class ConnectorSettings(BaseConnectorSettings):

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    criminal_ip: CriminalIPConfig = Field(default_factory=CriminalIPConfig)
