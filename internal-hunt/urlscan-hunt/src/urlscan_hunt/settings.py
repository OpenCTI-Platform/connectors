"""Configuration of the urlscan.io hunt connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class UrlscanHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the urlscan.io hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="63f252df-a47b-466d-97e0-5c32f0090c50",
    )
    name: str = Field(
        description="The name of the connector.",
        default="urlscan.io Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["urlscan"],
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run sends one search at a time). The platform budget is the minimum of its own setting and "
        "this value. Defaults to 2: urlscan.io counts searches per minute, hour and day, and asks API "
        "users to keep their concurrency low.",
        default=2,
        ge=1,
    )


class UrlscanHuntConfig(BaseConfigModel):
    """urlscan.io settings of the hunt connector."""

    api_key: SecretStr = Field(
        description="urlscan.io API key with search access.",
    )
    api_url: HttpUrl = Field(
        description="URL of urlscan.io (or of a dedicated urlscan Pro instance).",
        default=HttpUrl("https://urlscan.io"),
    )

    @field_validator("api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank API key."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the urlscan.io hunt connector."""

    connector: UrlscanHuntConnectorConfig = Field(
        default_factory=UrlscanHuntConnectorConfig
    )
    urlscan_hunt: UrlscanHuntConfig = Field(default_factory=UrlscanHuntConfig)
