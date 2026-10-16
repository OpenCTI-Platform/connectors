"""Configuration of the Silent Push hunt connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class SilentPushHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Silent Push hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="63c78100-7c2c-4f34-ab72-da67b30434a4",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Silent Push Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["silentpush"],
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run sends one search at a time). The platform budget is the minimum of its own setting and "
        "this value. Defaults to 2: Silent Push sets the number of API calls per subscription and does "
        "not publish a concurrency limit.",
        default=2,
        ge=1,
    )


class SilentPushHuntConfig(BaseConfigModel):
    """Silent Push settings of the hunt connector."""

    api_key: SecretStr = Field(
        description="Silent Push API key of a subscription that includes the web scan data API.",
    )
    api_url: HttpUrl = Field(
        description="URL of the Silent Push API.",
        default=HttpUrl("https://api.silentpush.com"),
    )
    create_certificates: bool = Field(
        description="Whether to create the X.509 certificates found (with their indicators).",
        default=True,
    )

    @field_validator("api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank API key."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Silent Push hunt connector."""

    connector: SilentPushHuntConnectorConfig = Field(
        default_factory=SilentPushHuntConnectorConfig
    )
    silentpush_hunt: SilentPushHuntConfig = Field(default_factory=SilentPushHuntConfig)
