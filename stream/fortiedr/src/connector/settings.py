from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="FortiEDR",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["fortiedr"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class FortiEDRConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the FortiEDR connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the FortiEDR Central Manager (e.g. https://console.fortiedr.example.com).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    organization: str = Field(
        description="FortiEDR organization name (required on multi-tenant consoles, used as the user prefix).",
        default="",
    )
    username: str = Field(
        description="FortiEDR REST API user name.",
    )
    password: SecretStr = Field(
        description="FortiEDR REST API user password.",
    )
    ip_set_name: str = Field(
        description="Name of the FortiEDR IP Set managed by this connector. It is created automatically if it does not exist yet.",
        default="OpenCTI",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the FortiEDR Central Manager.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `FortiEDRConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    fortiedr: FortiEDRConfig = Field(default_factory=FortiEDRConfig)
