from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """Connector-section configuration for the Zscaler STREAM connector.

    Mirrors the connector variables previously loaded via ``get_config_variable``.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Zscaler",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5ee2f825-634f-4f87-b305-15f97f6f7678",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["domain-name"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )


class ZscalerConfig(BaseConfigModel):
    """Zscaler-specific configuration (mirror of the existing ``zscaler`` variables)."""

    username: str = Field(
        description="Zscaler account username used for authentication.",
    )
    password: SecretStr = Field(
        description="Zscaler account password used for authentication.",
    )
    api_key: SecretStr = Field(
        description="Zscaler API key used to obfuscate the authenticated session.",
    )
    blacklist_name: str = Field(
        description="Name of the Zscaler URL category used as blacklist.",
        default="BLACK_LIST_DYNDNS",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates when connecting to OpenCTI.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Zscaler STREAM connector."""

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    zscaler: ZscalerConfig = Field(default_factory=ZscalerConfig)
