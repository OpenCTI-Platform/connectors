from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    # `id` is intentionally not given a default — it is required (inherited
    # from the SDK base) so each deployment must set a unique CONNECTOR_ID and
    # multiple instances cannot collide on the same connector identity.
    name: str = Field(
        default="CTM360-HackerView",
        description="Name of the connector.",
    )
    scope: ListFromString = Field(
        default=["CTM360-HackerView"],
        description="The scope of the connector.",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=24),
        description="The period of time to await between two runs of the connector.",
    )


class CTM360HackerviewFeedConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://hackerview.ctm360.com"),
        description="HackerView API base URL.",
    )
    api_key: SecretStr = Field(
        description="API key for HackerView authentication.",
    )
    import_issues: bool = Field(
        default=True,
        description="Enable importing security issues.",
    )
    import_resolved_issues: bool = Field(
        default=True,
        description="Enable importing resolved issues.",
    )
    import_domain_assets: bool = Field(
        default=True,
        description="Enable importing domain assets.",
    )
    import_host_assets: bool = Field(
        default=True,
        description="Enable importing hostname assets.",
    )
    import_ip_assets: bool = Field(
        default=True,
        description="Enable importing IP address assets.",
    )
    status_poll_interval: timedelta = Field(
        default=timedelta(hours=1),
        description="ISO-8601 duration between status polling cycles (default: PT1H).",
    )
    enable_status_tracking: bool = Field(
        default=True,
        description="Enable background polling for issue status changes.",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_hackerview_feed: CTM360HackerviewFeedConfig = Field(
        default_factory=CTM360HackerviewFeedConfig
    )
