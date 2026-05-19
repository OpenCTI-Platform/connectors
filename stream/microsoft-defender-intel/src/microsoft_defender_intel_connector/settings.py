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

    id: str = Field(
        description="The name of the connector.",
        default="4aa40d9f-bee0-466e-a72e-6878c13bde08",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Microsoft Defender Intel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["defender"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class MicrosoftDefenderIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftDefenderIntelConnector`.
    """

    tenant_id: str = Field(
        description="Your Azure App Tenant ID, see connector's README to help you find this information.",
    )
    client_id: str = Field(
        description="Your Azure App Client ID, see connector's README to help you find this information.",
    )
    client_secret: SecretStr = Field(
        description="Your Azure App Client secret, see connector's README to help you find this information.",
    )
    login_url: HttpUrl = Field(
        description="Login URL for Microsoft which is `https://login.microsoft.com`",
        default=HttpUrl("https://login.microsoft.com"),
    )
    base_url: HttpUrl = Field(
        description="The resource the API will use which is `https://api.securitycenter.microsoft.com`",
        default=HttpUrl("https://api.securitycenter.microsoft.com"),
    )
    resource_path: str = Field(
        description="The request URL that will be used which is `api/indicators`",
        default="api/indicators",
    )
    expire_time: int = Field(
        description="Number of days for your indicator to expire in Sentinel.",
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
        description="The action to apply if the indicator is matched from within the targetProduct security tool. "
        "`BlockAndRemediate` is not compatible with network indicators "
        "(see: https://learn.microsoft.com/en-us/defender-endpoint/indicator-manage)",
        default="Alert",
    )
    passive_only: bool = Field(
        description="Determines if the indicator should trigger an event that is visible to an end-user. "
        "When set to `True` security tools will not notify the end user that a 'hit' has occurred. "
        "This is most often treated as audit or silent mode by security products where they will simply "
        "log that a match occurred but will not perform the action.",
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
