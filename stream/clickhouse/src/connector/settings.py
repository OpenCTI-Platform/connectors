import re
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr, field_validator

# ClickHouse database/table names are interpolated into DDL/DML, so they are
# restricted to simple unquoted identifiers to avoid breakage and SQL injection.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ClickHouse",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["clickhouse"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class ClickHouseConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the ClickHouse connector.
    """

    base_url: HttpUrl = Field(
        description="Base URL of the ClickHouse HTTP interface (e.g. http://clickhouse:8123).",
        validation_alias=AliasChoices("base_url", "url"),
        serialization_alias="base_url",
    )
    username: str = Field(
        description="ClickHouse user name.",
        default="default",
    )
    password: SecretStr = Field(
        description="ClickHouse user password.",
        default=SecretStr(""),
    )
    database: str = Field(
        description="ClickHouse database to write to.",
        default="default",
    )
    table: str = Field(
        description="ClickHouse table that receives the OpenCTI stream events.",
        default="opencti_stream",
    )
    create_table: bool = Field(
        description="Whether to create the destination database and table automatically on startup.",
        default=True,
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the ClickHouse HTTP interface.",
        default=True,
    )

    @field_validator("database", "table")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_RE.match(value):
            raise ValueError(
                f"'{value}' is not a valid ClickHouse identifier; it must match "
                "[A-Za-z_][A-Za-z0-9_]* (it is interpolated into ClickHouse DDL/DML)."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `ClickHouseConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    clickhouse: ClickHouseConfig = Field(default_factory=ClickHouseConfig)
