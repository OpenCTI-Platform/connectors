from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from pydantic import Field


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="DatadogIntelConnector",
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
        default="live",  # listen the global stream (not filtered)
    )


class DatadogIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DatadogIntelConnector`.
    """

    integration_api_url: str = Field(
        description="Datadog's API URL as provided by the integration."
    )
    indicator_type: list[Literal["ip_address", "domain", "sha256"]] = Field(
        description="Types of indicators to send to the API.",
        default=["ip_address"],
    )
    dd_api_key: str = Field(
        description="Datadog's API key.",
    )
    dd_application_key: str = Field(
        description="Datadog's application key.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `DatadogIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    datadog_intel: DatadogIntelConfig = Field(default_factory=DatadogIntelConfig)
