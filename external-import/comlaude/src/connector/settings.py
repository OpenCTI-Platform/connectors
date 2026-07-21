from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Override BaseExternalImportConnectorConfig to set comlaude defaults."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6b120697-ca49-47bd-8a9e-eb26e948de5d",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Comlaude",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["comlaude", "stix"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=2),
    )


class ComlaudeConfig(BaseConfigModel):
    """Configuration specific to the Comlaude connector."""

    username: str = Field(
        description="ComLaude API username.",
    )
    password: SecretStr = Field(
        description="ComLaude API password.",
    )
    api_key: SecretStr = Field(
        description="ComLaude API key.",
    )
    group_id: str = Field(
        description="ComLaude group ID to search domains against.",
    )
    score: int = Field(
        description="Default score for created indicators (0-100).",
        default=0,
    )
    start_time: str = Field(
        description="Start time for domain search in ISO 8601 format.",
        default="1970-01-01T00:00:00Z",
    )
    labels: ListFromString = Field(
        description="Comma-separated labels to apply to created objects.",
        default=[],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Full settings for the Comlaude connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    comlaude: ComlaudeConfig = Field(default_factory=ComlaudeConfig)
