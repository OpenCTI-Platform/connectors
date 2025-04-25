import datetime
import os
from typing import Literal

from base_connector import BaseConnectorConfig
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class EmailIntelConfig(BaseModel):
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"]
    relative_import_start_date: datetime.timedelta

    host: str
    port: int
    username: str
    password: str
    mailbox: str


class ConnectorConfig(BaseConnectorConfig):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    email_intel_imap: EmailIntelConfig
