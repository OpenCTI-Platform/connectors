from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add the connector-specific
    `consumer_count` parameter used by the Splunk connector.
    """

    name: str = Field(default="Splunk", description="The name of the connector.")

    consumer_count: int = Field(
        description="Number of consumer/worker threads used to push data to Splunk.",
        default=10,
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[],
    )


class SplunkConfig(BaseConfigModel):
    """
    Configuration specific to the Splunk connector (mirror of the existing variables).
    """

    url: HttpUrl = Field(
        description="Base URL of the Splunk instance (e.g. https://splunk:8089).",
    )
    token: SecretStr = Field(
        description="Token used to authenticate against the Splunk API.",
    )
    auth_type: str = Field(
        description="Authorization scheme used with the Splunk token.",
        default="Bearer",
    )
    owner: str = Field(
        description="Splunk owner namespace used to access the KV Store collection.",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the Splunk instance.",
        default=True,
    )
    app: str = Field(
        description="Splunk app namespace hosting the KV Store collection.",
    )
    kv_store_name: str = Field(
        description="Name of the Splunk KV Store collection to feed.",
    )
    ignore_types: ListFromString = Field(
        description="Comma-separated list of entity types to ignore.",
        default=[],
    )


class MetricsConfig(BaseConfigModel):
    """
    Configuration for the optional Prometheus metrics server.
    """

    enable: bool = Field(
        description="Whether to expose Prometheus metrics.",
        default=False,
    )
    port: int = Field(
        description="Port on which metrics should be exposed.",
        default=9113,
    )
    addr: str = Field(
        description="IP address on which metrics should be exposed.",
        default="0.0.0.0",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig`,
    `SplunkConfig` and `MetricsConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
