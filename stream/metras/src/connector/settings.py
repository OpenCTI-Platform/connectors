"""Pydantic settings for the Metras Stream connector (STREAM)."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    name: str = Field(default="Metras-Stream", examples=["Metras-Stream"])
    scope: str = Field(default="Metras", examples=["Metras"])
    live_stream_id: str = Field(
        description="UUID of the OpenCTI live stream collection to consume "
        "(must be created and activated in Data > Data sharing > Live streams).",
        examples=["00000000-0000-0000-0000-000000000000"],
    )


class MetrasConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://api.metras.sa/api",
        description="Base URL of the Metras API.",
        examples=["https://api.metras.sa"],
    )
    api_key: SecretStr = Field(
        description="Metras API key (X-API-KEY header).", examples=["ChangeMe"]
    )
    verify_ssl: bool = Field(
        default=True, description="Verify TLS certificates.", examples=[True]
    )
    blocklist_action: Literal["ALERT", "BLOCK"] = Field(
        default="ALERT", description="Action for pushed blocklists.", examples=["ALERT"]
    )
    blocklist_platform: Literal["windows", "linux", "darwin"] = Field(
        default="windows",
        description="Default OS platform for blocklists.",
        examples=["windows"],
    )
    blocklist_severity: Literal[
        "Informational", "Low", "Medium", "High", "Critical"
    ] = Field(
        default="Medium",
        description="Default severity for blocklists.",
        examples=["Medium"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    metras: MetrasConfig = Field(default_factory=MetrasConfig)
