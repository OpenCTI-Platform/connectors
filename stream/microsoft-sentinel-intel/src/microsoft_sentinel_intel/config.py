import os

from base_connector.config import (
    BaseConnectorSettings,
    ListFromString,
    StreamConnectorConfig,
)
from base_connector.enums import LogLevelType
from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _StreamConnectorConfig(StreamConnectorConfig):
    live_stream_id: str

    name: str = Field(default="Microsoft Sentinel Intel Master")
    scope: ListFromString = Field(default=["sentinel"])
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)


class _MicrosoftSentinelIntelConfig(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str
    workspace_name: str
    subscription_id: str

    resource_group: str = Field(default="default")
    source_system: str = Field(default="Opencti Stream Connector")
    delete_extensions: bool = Field(default=True)
    extra_labels: ListFromString = Field(default=[])
    workspace_api_version: str = Field(default="2024-02-01-preview")
    management_api_version: str = Field(default="2025-03-01")


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(yaml_file=f"{_FILE_PATH}/../config.yml")

    connector: _StreamConnectorConfig
    microsoft_sentinel_intel: _MicrosoftSentinelIntelConfig
