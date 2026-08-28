"""Connector settings."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ConnectorConfig(BaseExternalImportConnectorConfig):
    """Generic connector configuration, with Wiz Cloud defaults."""

    name: str = Field(default="Wiz Cloud")
    scope: ListFromString = Field(default=["wiz-cloud"])
    duration_period: timedelta = Field(default=timedelta(hours=6))


class WizCloudConfig(BaseConfigModel):
    """Wiz specific configuration.

    Read from the WIZ_CLOUD_ environment prefix, or the wiz_cloud block in
    config.yml.
    """

    api_url: HttpUrl = Field(
        description="Tenant GraphQL endpoint, e.g. https://api.us17.app.wiz.io/graphql",
    )
    auth_url: HttpUrl = Field(
        default=HttpUrl("https://auth.app.wiz.io/oauth/token"),
        description="OAuth2 token endpoint (different host than api_url)",
    )
    client_id: SecretStr = Field(description="Wiz service account client id")
    client_secret: SecretStr = Field(description="Wiz service account client secret")

    issue_severity: ListFromString = Field(
        default=["CRITICAL", "HIGH"],
        description=(
            "Issue severities to import (comma-separated). "
            "E.g. 'CRITICAL,HIGH,MEDIUM,LOW,INFORMATIONAL'."
        ),
    )
    issue_status: ListFromString = Field(
        default=["OPEN", "IN_PROGRESS"],
        description=(
            "Issue statuses to import (comma-separated). "
            "E.g. 'OPEN,IN_PROGRESS,RESOLVED,REJECTED'."
        ),
    )

    # pydantic parses ISO 8601 durations, so WIZ_CLOUD_SINCE=P30D works.
    since: timedelta = Field(
        default=timedelta(days=30),
        description="Relative import start on first run (ISO 8601 duration)",
    )

    page_size: int = Field(default=50, ge=1, le=100)
    marking: TLPLevel = Field(default=TLPLevel.AMBER_STRICT)


class ConnectorSettings(BaseConnectorSettings):
    """Full settings tree loaded from the environment or config.yml."""

    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    wiz_cloud: WizCloudConfig
