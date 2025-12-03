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
        default="MicrosoftSentinelIntel",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
        default="live",  # listen the global stream (not filtered)
    )


class MicrosoftSentinelIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftSentinelIntelConnector`.
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
    workspace_id: str = Field(
        description="Your Azure Workspace ID",
    )
    workspace_name: str = Field(
        description="The name of the log analytics workspace",
    )
    subscription_id: str = Field(
        description="The subscription id where the Log Analytics is",
    )
    resource_group: str = Field(
        description="The name of the resource group where the log analytics is",
        default="default",
        deprecated=True,
    )
    source_system: str = Field(
        description="The name of the source system displayed in Microsoft Sentinel",
        default="Opencti Stream Connector",
    )
    delete_extensions: bool = Field(
        description="Delete the extensions in the stix bundle sent to the SIEM",
        default=True,
    )
    extra_labels: list[str] = Field(
        description="Extra labels added to the bundle sent. String separated by comma",
        default=[],
    )
    workspace_api_version: str = Field(
        description="API version of the Microsoft log analytics workspace interface",
        default="2024-02-01-preview",
    )
    management_api_version: str = Field(
        description="API version of the Microsoft management interface",
        default="2025-03-01",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `MicrosoftSentinelIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    microsoft_sentinel_intel: MicrosoftSentinelIntelConfig = Field(
        default_factory=MicrosoftSentinelIntelConfig
    )
