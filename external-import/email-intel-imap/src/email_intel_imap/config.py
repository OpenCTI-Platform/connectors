import datetime
import os
from typing import Literal

from base_connector.config import BaseConnectorSettings, ConnectorConfig, ListFromString
from base_connector.enums import LogLevelType
from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    id: str = Field(default="email-intel-imap--ee2beb6c-4e99-47e6-ab5b-f3eea350f601")
    name: str = Field(default="Email Intel IMAP")
    scope: ListFromString = Field(default=["email-intel-imap"])
    duration_period: datetime.timedelta = Field(default=datetime.timedelta(hours=1))
    log_level: LogLevelType = Field(default=LogLevelType.ERROR)


class _EmailIntelConfig(BaseModel):
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(default="amber+strict")
    )
    relative_import_start_date: datetime.timedelta = Field(
        default=datetime.timedelta(days=30)
    )

    host: str
    port: int = Field(default=993)
    username: str
    password: SecretStr | None = Field(default=None)
    google_token_json: SecretStr | None = Field(
        default=None, description="Content of the token.json file from Google API"
    )
    mailbox: str = Field(default="INBOX")
    attachments_mime_types: ListFromString = Field(
        default=["application/pdf", "text/csv", "text/plain"]
    )

    @model_validator(mode="after")
    def check_auth(self: "_EmailIntelConfig") -> "_EmailIntelConfig":
        """Check the autentivication method."""
        # Condition fo unicity to select proprer adapter should be added here
        # Only one of these conditions must be True
        conditions = [
            self.password is not None
            and all(other is None for other in [self.google_token_json]),
            self.google_token_json is not None
            and all(other is None for other in [self.password]),
        ]
        if sum(conditions) != 1:
            raise ValueError("Auth method is not valid.")
        return self


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    email_intel_imap: _EmailIntelConfig
