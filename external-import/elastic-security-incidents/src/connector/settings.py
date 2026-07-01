from datetime import timedelta
from typing import Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d790f4c0-84c1-4e91-8e6b-3a6f3a0e1234",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Elastic Security Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["elastic-security-incidents"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=30),
    )


class ElasticSecurityConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Elastic Security Incidents connector.
    """

    url: str = Field(
        description="The Elasticsearch URL (for alerts) or Kibana URL (for cases).",
    )
    api_key: SecretStr = Field(
        description="The Elasticsearch API Key.",
    )
    kibana_url: Optional[str] = Field(
        description="The Kibana URL (optional, required for cases if different from Elasticsearch URL).",
        default=None,
    )
    ca_cert: Optional[str] = Field(
        description="Path to CA certificate for SSL verification (optional).",
        default=None,
    )
    verify_ssl: bool = Field(
        description="Whether to verify SSL certificates.",
        default=True,
    )
    import_start_date: Optional[str] = Field(
        description="Initial import start date in ISO-8601 format (e.g. 2024-01-01T00:00:00Z).",
        default=None,
    )
    import_alerts: bool = Field(
        description="Whether to import security alerts.",
        default=True,
    )
    import_cases: bool = Field(
        description="Whether to import security cases (requires Kibana URL).",
        default=True,
    )
    alert_statuses: ListFromString = Field(
        description="Alert statuses to import (comma-separated). Leave empty to import all.",
        default=[],
    )
    alert_rule_tags: ListFromString = Field(
        description="Alert rule tags to filter by (comma-separated). Leave empty to import all.",
        default=[],
    )
    case_statuses: ListFromString = Field(
        description="Case statuses to import (comma-separated). Leave empty to import all.",
        default=[],
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ElasticSecurityConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    elastic_security: ElasticSecurityConfig = Field(
        default_factory=ElasticSecurityConfig
    )
