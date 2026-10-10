"""Configuration of the Elastic Security hunt connector."""

from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class ElasticSecurityHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Elastic Security hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4d7e2b91-6a3f-4c58-8e0b-2f9a1c6d5e73",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Elastic Security Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["elastic-security"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Elastic Security",
    )


class ElasticSecurityHuntConfig(BaseConfigModel):
    """Elasticsearch settings of the hunt connector."""

    url: HttpUrl = Field(
        description="URL of the Elasticsearch cluster, e.g. 'https://elastic.example.com:9200'.",
    )
    api_key: SecretStr | None = Field(
        description="Elasticsearch API key, encoded (the base64 'id:api_key' value). "
        "Leave empty to use username and password.",
        default=None,
    )
    username: str | None = Field(
        description="Elasticsearch user name, used when no API key is set.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="Elasticsearch user password, used when no API key is set.",
        default=None,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TLS certificate of the cluster.",
        default=True,
    )
    ca_cert: str | None = Field(
        description="Path to a CA certificate bundle verifying the cluster certificate.",
        default=None,
    )
    indices: ListFromString = Field(
        description="Index patterns the hunts search (EQL and Lucene queries, and the ES|QL "
        "queries translated from Sigma rules).",
        default=["logs-*", "winlogbeat-*", "filebeat-*", "auditbeat-*", "endgame-*"],
        min_length=1,
    )
    query_language: Literal["esql", "eql", "lucene"] = Field(
        description="Language Sigma rules are translated into: 'esql' (ES|QL, Elasticsearch 8.13+), "
        "'eql' or 'lucene'.",
        default="esql",
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': 'ecs_windows', "
        "'ecs_windows_old', 'ecs_kubernetes', 'ecs_macos_esf', 'ecs_zeek_beats', 'ecs_zeek_corelight', "
        "'zeek' or 'none'.",
        default="ecs_windows",
    )
    timestamp_field: str = Field(
        description="Field holding the event time, used to restrict the queries to the run window.",
        default="@timestamp",
    )

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require an API key, or a user name and a password."""
        has_api_key = bool(self.api_key and self.api_key.get_secret_value().strip())
        has_basic = bool(
            self.username and self.password and self.password.get_secret_value().strip()
        )
        if not has_api_key and not has_basic:
            raise ValueError("Set api_key, or username and password.")
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Elastic Security hunt connector."""

    connector: ElasticSecurityHuntConnectorConfig = Field(
        default_factory=ElasticSecurityHuntConnectorConfig
    )
    elastic_security_hunt: ElasticSecurityHuntConfig = Field(
        default_factory=ElasticSecurityHuntConfig
    )
