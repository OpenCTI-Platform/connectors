from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
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
    scope: ListFromString = Field(
        description="The scope of the stream connector.",
        default=["sentinel"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )
    live_stream_listen_delete: bool = Field(
        description="Whether to listen for delete events in the live stream.",
        default=True,
    )
    live_stream_no_dependencies: bool = Field(
        description="Whether to avoid fetching dependencies for the objects received in the live stream.",
        default=True,
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
    extra_labels: ListFromString = Field(
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
