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
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="c2d8a1b4-5f3e-4d7a-9b6c-1e2f3a4b5c6d",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Sumo Logic Intel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["sumologic"],
    )
    live_stream_id: str = Field(
        description="The ID of the live stream to connect to.",
    )


class SumologicIntelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SumologicIntelConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="The base URL of the Sumo Logic API.",
    )
    access_id: str = Field(
        description="The Sumo Logic access ID used to authenticate against the API.",
    )
    access_key: SecretStr = Field(
        description="The Sumo Logic access key used to authenticate against the API.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `SumologicIntelConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    sumologic_intel: SumologicIntelConfig = Field(default_factory=SumologicIntelConfig)
