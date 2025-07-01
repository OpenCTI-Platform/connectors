import datetime
import os

from base_connector_config import (
    BaseConnectorSettings,
    ConnectorConfig,
    ListFromString,
    LogLevelType,
)
from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    name: str = Field(
        description="Name of the connector",
        min_length=1,
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        min_length=1,
    )
    log_level: LogLevelType = Field(
        default=LogLevelType.ERROR, description="Determines the verbosity of the logs"
    )
    duration_period: datetime.timedelta = Field(
        default=datetime.timedelta(minutes=10),
        description="Duration between two scheduled runs of the connector (ISO 8601 format)",
    )


class _RansomwareConfig(BaseModel):
    pull_history: bool = Field(
        default=False, description="Whether to pull historic data"
    )
    history_start_year: int = Field(default=2023, description="The year to start from")
    create_threat_actor: bool = Field(
        default=False, description="Whether to create a Threat Actor object"
    )


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    ransomware: _RansomwareConfig
