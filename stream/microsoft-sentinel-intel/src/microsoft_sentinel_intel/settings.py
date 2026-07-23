from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


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


class MicrosoftSentinelIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftSentinelIntelConnector`.
    """

    tenant_id: str | None = Field(
        default=None,
        description="Your Azure App Tenant ID, see the screenshot to help you find this information.",
    )
    client_id: str | None = Field(
        default=None,
        description="Your Azure App Client ID, see the screenshot to help you find this information.",
    )
    client_secret: SecretStr | None = Field(
        default=None,
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
    # TODO: remove management_api_version config var (not used anymore)
    management_api_version: str = Field(
        description="API version of the Microsoft management interface",
        default="2025-03-01",
    )
    query_api_version: str = Field(
        description="API version of the Microsoft Sentinel threat-intel /query endpoint",
        default="2025-07-01-preview",
    )
    batch_mode: bool = Field(
        description="Enable batch mode for bulk uploading STIX objects. When disabled (default), objects are sent individually in real-time.",
        default=False,
    )
    batch_size: int = Field(
        description="Maximum number of unique STIX objects to accumulate before flushing a batch. Only used when batch_mode is enabled. Maxed at 100 because the Sentinel Upload Indicators API rejects requests containing more than 100 STIX objects.",
        default=100,
        ge=1,
        le=100,
    )
    batch_timeout: int = Field(
        description="Maximum time in seconds to wait before flushing a partial batch. Only used when batch_mode is enabled.",
        default=30,
        ge=1,
    )
    event_types: ListFromString = Field(
        description="Comma-separated list of event types to process (create, update, delete). Defaults to all three; a single instance handles every event type. Restrict this only if you want to split the workload across dedicated instances.",
        default=["create", "update", "delete"],
    )
    publish_identities: bool = Field(
        description="Also push STIX Identity objects (e.g. an indicator's author) received from the stream to Microsoft Sentinel, in addition to Indicators, so their display name resolves correctly instead of only showing the identifier.",
        default=False,
    )

    @model_validator(mode="after")
    def check_auth_fields_consistency(self) -> "MicrosoftSentinelIntelConfig":
        values = {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_secret": (
                self.client_secret.get_secret_value()
                if self.client_secret is not None
                else None
            ),
        }
        blank_fields = [
            name
            for name, value in values.items()
            if value is not None and not value.strip()
        ]
        if blank_fields:
            raise ValueError(
                f"{', '.join(blank_fields)} must not be empty or whitespace-only."
            )

        provided = [value is not None for value in values.values()]
        if any(provided) and not all(provided):
            raise ValueError(
                "If you provide any of tenant_id, client_id, or client_secret, you must provide all three."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `MicrosoftSentinelIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    microsoft_sentinel_intel: MicrosoftSentinelIntelConfig = Field(
        default_factory=MicrosoftSentinelIntelConfig
    )
