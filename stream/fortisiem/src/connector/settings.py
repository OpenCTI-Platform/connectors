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
        default="FortiSIEM",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["fortisiem"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class FortiSIEMConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the FortiSIEM connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the FortiSIEM Supervisor (e.g. https://fortisiem.example.com).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    organization: str = Field(
        description="FortiSIEM organization used to scope the REST API user (e.g. 'super').",
        default="super",
    )
    username: str = Field(
        description="FortiSIEM REST API user name.",
    )
    password: SecretStr = Field(
        description="FortiSIEM REST API user password.",
    )
    watchlist_id: int = Field(
        description="Numeric ID of the FortiSIEM Watch List that receives the IOCs.",
    )
    entry_age_out: str = Field(
        description="Age-out applied to Watch List entries so they expire automatically (e.g. '30d').",
        default="30d",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the FortiSIEM Supervisor.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `FortiSIEMConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    fortisiem: FortiSIEMConfig = Field(default_factory=FortiSIEMConfig)
