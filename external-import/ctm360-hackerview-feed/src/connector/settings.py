from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        default="5f75b6cc-25a3-43aa-90ad-089beb2fd832",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
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
        description="Interval in seconds between status polling cycles (default: 1h).",
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
