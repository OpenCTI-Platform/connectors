from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Configuration for STREAM connector behavior
    """

    name: str = Field(
        default="Akamai Connector",
        description="Connector name",
    )

    scope: ListFromString = Field(
        default=["indicator"],
        description="Connector scope",
    )

    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="info",
        description="Logging level",
    )

    live_stream_id: str = Field(
        default="live",
        description="Live stream ID",
    )


class AkamaiConfig(BaseConfigModel):
    """
    Akamai configuration
    """

    base_url: HttpUrl
    client_token: SecretStr
    client_secret: SecretStr
    access_token: SecretStr

    # NOTE:
    # This represents a single Akamai Client List ID (not a list of IPs).
    # Kept as-is to stay aligned with Akamai API usage and avoid overcomplicating the connector.
    client_list_id: str = Field(description="Target Client List ID")


class ConnectorSettings(BaseConnectorSettings):
    """
    Global connector settings
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    akamai: AkamaiConfig = Field(default_factory=AkamaiConfig)
