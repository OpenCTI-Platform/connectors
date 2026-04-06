from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(default="CTM360-HackerView")


class CTM360HvConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://hackerview.ctm360.com",
        description="HackerView API base URL.",
    )
    api_key: str = Field(description="API key for HackerView authentication.")
    import_interval: int = Field(
        default=86400,
        description="Interval in seconds between imports (default: 24h).",
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
    status_poll_interval: int = Field(
        default=3600,
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
    ctm360_hv: CTM360HvConfig = Field(default_factory=CTM360HvConfig)
