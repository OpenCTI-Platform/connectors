import datetime
import os
import warnings
from typing import Any, Literal

from lib.base_connector_config import (
    BaseConnectorSettings,
    ConnectorConfig,
    ListFromString,
    LogLevelType,
)
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    name: str = Field(default="Shadowserver")
    scope: ListFromString = Field(default=["stix2"])
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(days=1))

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated(cls, data: Any) -> datetime.timedelta:
        if run_every := data.pop("run_every", "").upper():
            # run_every is deprecated. This is a workaround to keep the old config working
            # while we migrate to duration_period.
            warnings.warn(
                "CONNECTOR_RUN_EVERY is deprecated. Use CONNECTOR_DURATION_PERIOD instead."
            )
            if data.get("duration_period"):
                raise ValueError("Cannot set both run_every and duration_period.")
            if run_every[-1] in ["H", "M", "S"]:
                data["duration_period"] = (
                    f"PT{int(float(run_every[:-1]))}{run_every[-1]}"
                )
            else:
                data["duration_period"] = (
                    f"P{int(float(run_every[:-1]))}{run_every[-1]}"
                )
        return data


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
