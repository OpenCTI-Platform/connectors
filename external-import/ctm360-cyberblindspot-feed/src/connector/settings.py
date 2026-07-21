from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(default="CTM360-CyberBlindSpot")


class CTM360CbsConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://cbs.ctm360.com",
        description="CyberBlindSpot API base URL.",
    )
    api_key: SecretStr = Field(description="API key for CyberBlindSpot authentication.")
    import_interval: int = Field(
        default=86400,
        gt=0,
        description="Interval in seconds between imports (default: 24h).",
    )
    import_incidents: bool = Field(
        default=True,
        description="Enable importing incidents.",
    )
    import_malware_logs: bool = Field(
        default=True,
        description="Enable importing malware logs.",
    )
    import_breached_credentials: bool = Field(
        default=True,
        description="Enable importing breached credentials.",
    )
    import_card_leaks: bool = Field(
        default=True,
        description="Enable importing card leaks.",
    )
    import_domain_protection: bool = Field(
        default=True,
        description="Enable importing domain protection findings.",
    )
    status_poll_interval: int = Field(
        default=3600,
        gt=0,
        description="Interval in seconds between status polling cycles (default: 1h).",
    )
    enable_status_tracking: bool = Field(
        default=True,
        description="Enable background polling for incident status changes.",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_cbs: CTM360CbsConfig = Field(default_factory=CTM360CbsConfig)
