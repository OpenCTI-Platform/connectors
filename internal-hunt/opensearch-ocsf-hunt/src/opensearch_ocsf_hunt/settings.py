"""Configuration of the OpenSearch OCSF hunt connector."""

from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class OpenSearchOcsfHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the OpenSearch OCSF hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6c1f8a3e-2d47-4b9e-8f05-3a7d9e1c2b64",
    )
    name: str = Field(
        description="The name of the connector.",
        default="OpenSearch OCSF Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["opensearch"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="OpenSearch",
    )


class OpenSearchOcsfHuntConfig(BaseConfigModel):
    """OpenSearch settings of the hunt connector."""

    url: HttpUrl = Field(
        description="URL of the OpenSearch cluster, e.g. 'https://opensearch.example.com:9200'.",
    )
    username: str | None = Field(
        description="OpenSearch user name (basic authentication). Leave empty for a cluster "
        "without the security plugin.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="OpenSearch user password.",
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
        description="Index patterns holding the OCSF events the hunts search.",
        default=["ocsf-*"],
        min_length=1,
    )
    query_language: Literal["ppl", "opensearch-lucene"] = Field(
        description="Language Sigma rules are translated into: 'ppl' (Piped Processing Language) "
        "or 'opensearch-lucene' (Lucene query string).",
        default="ppl",
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': 'ocsf' or 'none'.",
        default="ocsf",
    )
    timestamp_field: str = Field(
        description="Field holding the event time, used to restrict the queries to the run window.",
        default="time",
    )
    timestamp_format: Literal["epoch_millis", "date"] = Field(
        description="Type of the timestamp field: 'epoch_millis' (a number of milliseconds, the "
        "OCSF 'time' attribute) or 'date' (a date field such as 'time_dt').",
        default="epoch_millis",
    )

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require the user name and the password together."""
        has_password = bool(self.password and self.password.get_secret_value().strip())
        if bool(self.username) != has_password:
            raise ValueError("Set both username and password, or neither.")
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the OpenSearch OCSF hunt connector."""

    connector: OpenSearchOcsfHuntConnectorConfig = Field(
        default_factory=OpenSearchOcsfHuntConnectorConfig
    )
    opensearch_ocsf_hunt: OpenSearchOcsfHuntConfig = Field(
        default_factory=OpenSearchOcsfHuntConfig
    )
