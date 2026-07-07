import re
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr, field_validator

# The topic is interpolated into the HTTP Proxy URL path (/topics/<topic>), so it
# is restricted to the Kafka/Redpanda topic charset to fail fast on a misconfigured
# name instead of building a malformed URL.
_TOPIC_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Redpanda",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, used to filter the live stream events.",
        default=["redpanda"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    live_stream_id: str = Field(
        description="The ID of the OpenCTI live stream to connect to.",
    )


class RedpandaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Redpanda connector.
    """

    http_proxy_url: HttpUrl = Field(
        description="Base URL of the Redpanda HTTP Proxy / Pandaproxy (e.g. http://redpanda:8082).",
        validation_alias=AliasChoices("http_proxy_url", "url"),
        serialization_alias="http_proxy_url",
    )
    topic: str = Field(
        description="Redpanda topic that receives the OpenCTI stream events.",
        default="opencti",
    )
    username: str = Field(
        description="Optional user name for HTTP basic authentication against the proxy.",
        default="",
    )
    password: SecretStr = Field(
        description="Optional password for HTTP basic authentication against the proxy.",
        default=SecretStr(""),
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the Redpanda HTTP Proxy.",
        default=True,
    )

    @field_validator("topic")
    @classmethod
    def _validate_topic(cls, value: str) -> str:
        if value in (".", "..") or len(value) > 249 or not _TOPIC_RE.match(value):
            raise ValueError(
                f"'{value}' is not a valid Kafka/Redpanda topic name; it must match "
                "[A-Za-z0-9._-] (max 249 chars) and cannot be '.' or '..' "
                "(it is interpolated into the HTTP Proxy URL path)."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `RedpandaConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    redpanda: RedpandaConfig = Field(default_factory=RedpandaConfig)
