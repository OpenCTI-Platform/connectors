import datetime
import os
from typing import Any, Literal

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

    @model_validator(mode="before")
    def check_auth(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Check the autentivication method."""
        # Condition fo unicity to select proprer adapter should be added here
        # Only one of these conditions must be True
        password = values.get("password")
        google_token_json = values.get("google_token_json")
        if (password and google_token_json) or not (password or google_token_json):
            raise ValueError(
                "Auth method is not valid. Either password or Google token must be set."
            )
        return values


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig
    email_intel_imap: _EmailIntelConfig
