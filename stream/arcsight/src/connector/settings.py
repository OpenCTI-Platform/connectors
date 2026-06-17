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
        default="ArcSight",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["arcsight"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class ArcSightConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the ArcSight connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the ArcSight ESM Manager (e.g. https://arcsight.example.com:8443).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    username: str = Field(
        description="ArcSight ESM user name.",
    )
    password: SecretStr = Field(
        description="ArcSight ESM user password.",
    )
    active_list_id: str = Field(
        description="Resource ID of the ArcSight Active List that receives the IOCs.",
    )
    value_column: str = Field(
        description="Name of the Active List column that stores the IOC value.",
        default="value",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the ArcSight ESM Manager.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `ArcSightConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    arcsight: ArcSightConfig = Field(default_factory=ArcSightConfig)
