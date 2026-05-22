from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="TAXII POST",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["taxii"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class TaxiiConfig(BaseConfigModel):
    url: HttpUrl = Field(
        description="The URL of the TAXII server.",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates.",
        default=True,
    )
    api_root: str = Field(
        description="The TAXII API root path segment.",
        default="root",
    )
    collection_id: str = Field(
        description="The target TAXII collection ID.",
    )
    token: SecretStr | None = Field(
        description="Bearer token for authentication. Takes precedence over basic auth.",
        default=None,
    )
    login: SecretStr | None = Field(
        description="Username for basic auth.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="Password for basic auth.",
        default=None,
    )
    version: str = Field(
        description="TAXII protocol version.",
        default="2.1",
    )
    stix_version: str = Field(
        description="STIX output version.",
        default="2.1",
    )
    delete_created_by_ref: bool = Field(
        description="Strip created_by_ref from objects before posting.",
        default=True,
    )
    delete_marking_definition: bool = Field(
        description="Strip object_marking_refs from objects before posting.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    taxii: TaxiiConfig = Field(default_factory=TaxiiConfig)
