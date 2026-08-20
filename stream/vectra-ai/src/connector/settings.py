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
        default="Vectra AI Intel",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["vectra-ai"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class VectraAIConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Vectra AI Intel connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the Vectra AI Platform (e.g. https://vectra.example.com).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    api_token: SecretStr = Field(
        description="API token used to authenticate against the Vectra AI API.",
        validation_alias=AliasChoices("api_token", "token"),
        serialization_alias="api_token",
    )
    api_version: str = Field(
        description="Version of the Vectra API used to reach the threat feed endpoints.",
        default="v2.5",
    )
    feed_name: str = Field(
        description=(
            "Name of the Vectra threat feed managed by this connector. "
            "It is created automatically if it does not exist yet."
        ),
        default="OpenCTI",
    )
    feed_category: Literal["cnc", "malware", "recon", "exfil", "lateral"] = Field(
        description="Detection category assigned to the Vectra threat feed.",
        default="cnc",
    )
    feed_certainty: Literal["Low", "Medium", "High"] = Field(
        description="Certainty assigned to indicators matched against the threat feed.",
        default="High",
    )
    feed_duration: int = Field(
        description=(
            "Number of days indicators remain active in the Vectra threat feed "
            "before they expire."
        ),
        default=14,
        ge=1,
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the Vectra AI API.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `VectraAIConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    vectra_ai: VectraAIConfig = Field(default_factory=VectraAIConfig)
