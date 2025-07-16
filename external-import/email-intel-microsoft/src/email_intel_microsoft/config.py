import datetime
import os
from typing import Literal

from base_connector.config import BaseConnectorSettings, ConnectorConfig, ListFromString
from base_connector.enums import LogLevelType
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    name: str = Field(default="Email Intel Microsoft")
    scope: ListFromString = Field(default=["email-intel-microsoft"])
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(hours=1))
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)


class _EmailIntelMicrosoftConfig(BaseModel):
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(default="amber+strict")
    )
    relative_import_start_date: datetime.timedelta = Field(
        default=datetime.timedelta(days=30)
    )

    tenant_id: str
    client_id: str
    client_secret: str
    email: EmailStr
    mailbox: str = Field(default="INBOX")
    attachments_mime_types: ListFromString = Field(
        default=["application/pdf", "text/csv", "text/plain"]
    )


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    email_intel_microsoft: _EmailIntelMicrosoftConfig
