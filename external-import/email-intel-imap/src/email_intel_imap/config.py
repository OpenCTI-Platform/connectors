import datetime
import os
from typing import Any, Literal

from base_connector.config import BaseConnectorSettings, ConnectorConfig, ListFromString
from base_connector.enums import LogLevelType
from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import SettingsConfigDict

_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class _ConnectorConfig(ConnectorConfig):
    id: str = Field(
        default="email-intel-imap--ee2beb6c-4e99-47e6-ab5b-f3eea350f601",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Email Intel IMAP",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["email-intel-imap"],
        description="The scope of the connector.",
    )
    duration_period: datetime.timedelta = Field(
        default=datetime.timedelta(hours=1),
        description="The period of time to await between two runs of the connector.",
    )
    log_level: LogLevelType = Field(
        default=LogLevelType.ERROR,
        description="The minimum level of logs to display.",
    )


class _EmailIntelConfig(BaseModel):
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(
            default="amber+strict",
            description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
        )
    )
    relative_import_start_date: datetime.timedelta = Field(
        default=datetime.timedelta(days=30),
        description="The relative start date to import emails in ISO 8601 duration format (e.g. P30D for 30 days).",
    )

    host: str = Field(
        description="IMAP server hostname or IP address",
    )
    port: int = Field(
        default=993,
        description="IMAP server port number",
    )
    username: str = Field(
        description="Username to authenticate to the IMAP server. Either `password` or `google_token_json` must be set as well.",
    )
    password: SecretStr | None = Field(
        default=None,
        description="Password to authenticate to the IMAP server. Either `password` or `google_token_json` must be set.",
    )
    google_token_json: SecretStr | None = Field(
        default=None,
        description="Content of the token.json file from Google API. Either `password` or `google_token_json` must be set.",
    )
    mailbox: str = Field(
        default="INBOX",
        description="The mailbox to monitor (e.g., INBOX)",
    )
    attachments_mime_types: ListFromString = Field(
        default=["application/pdf", "text/csv", "text/plain"],
        description="List of attachment MIME types to process (comma-separated)",
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
                "Auth method is not valid. Either password or Google token must be set. "
                "Providing both or neither will cause this error."
            )
        return values


class ConnectorSettings(BaseConnectorSettings):
    model_config = SettingsConfigDict(
        yaml_file=f"{_FILE_PATH}/../../config.yml",
        env_file=f"{_FILE_PATH}/../../.env",
    )

    connector: _ConnectorConfig = Field(
        default_factory=_ConnectorConfig,
        description="Connector configurations.",
    )
    email_intel_imap: _EmailIntelConfig = Field(
        default_factory=_EmailIntelConfig,
        description="Email Intel IMAP connector configurations.",
    )
