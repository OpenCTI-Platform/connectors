from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(default="CTM360-CYNA")


class CTM360CynaConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://cyna.ctm360.com",
        description="CYNA API base URL.",
    )
    api_key: SecretStr = Field(description="API key for CYNA authentication.")
    import_interval: int = Field(
        default=86400,
        gt=0,
        description="Interval in seconds between imports (default: 24h).",
    )
    page_size: int = Field(
        default=25,
        gt=0,
        description="Number of news items per API page (default: 25).",
    )
    max_pages: int = Field(
        default=100,
        gt=0,
        description="Maximum pages to fetch per import cycle (safety limit).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_cyna: CTM360CynaConfig = Field(default_factory=CTM360CynaConfig)
