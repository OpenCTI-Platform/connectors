import datetime
import os
from typing import Literal

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
    name: str = Field(default="Shadowserver")
    scope: ListFromString = Field(default=["stix2"])
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(days=1))
    run_every: str = Field(default="1d")


class _ShadowserverConfig(BaseModel):
    marking: Literal["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"] = (
        Field(default="TLP:CLEAR")
    )
    api_key: str
    api_secret: str
    create_incident: bool = Field(default=False)
    incident_severity: str = Field(default="low")
    incident_priority: str = Field(default="P4")


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    shadowserver: _ShadowserverConfig
