import datetime
import os

from lib.base_connector_config import (
    BaseConnectorSettings,
    ConnectorConfig,
    ListFromString,
    LogLevelType,
)
from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    name: str = Field(default="Ransomware Connector")
    scope: ListFromString = Field(default=["stix2"])
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(minutes=10))


class _RansomwareConfig(BaseModel):
    pull_history: bool = Field(default=False)
    history_start_year: int = Field(default=2023)
    create_threat_actor: bool = Field(default=False)
    interval: str = Field(default=None)  # Warning Deprecated


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    ransomware: _RansomwareConfig
