from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Configuration specific to the PromptIntel external import connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="a7e1c3d2-5f4b-4e89-9c1a-3b8d7f6e2a90",
    )
    name: str = Field(
        description="The name of the connector.",
        default="PromptIntel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["promptintel"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class PromptIntelConfig(BaseConfigModel):
    """PromptIntel-specific configuration parameters."""

    api_url: str = Field(
        description="Base URL for the PromptIntel API.",
        default="https://api.promptintel.novahunting.ai/api/v1",
    )
    api_key: str = Field(
        description="API key for authenticating with PromptIntel.",
    )
    tlp_level: str = Field(
        description="TLP marking level: clear, green, amber, amber+strict, red.",
        default="clear",
    )
    severity_filter: str = Field(
        description="Filter prompts by severity: critical, high, medium, low. Empty for all.",
        default="",
    )
    category_filter: str = Field(
        description="Filter prompts by category: manipulation, abuse, patterns, outputs. Empty for all.",
        default="",
    )
    import_start_limit: int = Field(
        description="Maximum number of prompts to fetch on the first run (historical backfill).",
        default=5000,
    )
    import_limit: int = Field(
        description="Maximum number of prompts to fetch on subsequent runs.",
        default=1000,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the PromptIntel connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    promptintel: PromptIntelConfig = Field(default_factory=PromptIntelConfig)
