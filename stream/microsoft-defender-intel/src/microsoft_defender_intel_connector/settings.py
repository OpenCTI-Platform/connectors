from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="MicrosoftDefenderIntel",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
        default="live",  # listen the global stream (not filtered)
    )


class MicrosoftDefenderIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftDefenderIntelConnector`.
    """

    tenant_id: str = Field(
        description="Your Azure App Tenant ID, see the screenshot to help you find this information.",
    )
    client_id: str = Field(
        description="Your Azure App Client ID, see the screenshot to help you find this information.",
    )
    client_secret: SecretStr = Field(
        description="Your Azure App Client secret, See the screenshot to help you find this information.",
    )
    login_url: str = Field(
        description="Login URL for Microsoft which is `https://login.microsoft.com`",
        default="https://login.microsoft.com",
    )
    base_url: str = Field(
        description="The resource the API will use which is `https://api.securitycenter.microsoft.com`",
        default="https://api.securitycenter.microsoft.com",
    )
    resource_path: str = Field(
        description="The request URL that will be used which is `/api/indicators`",
        default="/api/indicators",
    )
    expire_time: int = Field(
        description="Number of days for your indicator to expire in Sentinel. Suggestion of `30` as a default",
        default=30,
    )
    action: Literal[
        "Warn",
        "Block",
        "Audit",
        "Alert",
        "AlertAndBlock",
        "BlockAndRemediate",
        "Allowed",
    ] = Field(
        description="The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: `Warn`, `Block`, `Audit`, `Alert`, `AlertAndBlock`, `BlockAndRemediate`, `Allowed`. `BlockAndRemediate` is not compatible with network indicators (see: https://learn.microsoft.com/en-us/defender-endpoint/indicator-manage)",
        default="Alert",
    )
    passive_only: bool = Field(
        description="Determines if the indicator should trigger an event that is visible to an end-user. When set to `True` security tools will not notify the end user that a â€˜hitâ€™ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is `False`.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `MicrosoftDefenderIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    microsoft_defender_intel: MicrosoftDefenderIntelConfig = Field(
        default_factory=MicrosoftDefenderIntelConfig
    )
