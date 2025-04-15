import os
from typing import Literal

from base_connector.config import BaseConnectorConfig
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class EmailIntelConfig(BaseModel):
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"]


class ConnectorConfig(BaseConnectorConfig):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    email_intel_imap: EmailIntelConfig

    @property
    def tlp_level(
        self,
    ) -> Literal["white", "clear", "green", "amber", "amber+strict", "red"]:
        return self.email_intel_imap.tlp_level
