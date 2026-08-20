from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="e2f3a4b5-c6d7-4e8f-9a0b-1c2d3e4f5a6b",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ANY.RUN TI Feed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["anyrun-feed"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=2),
    )


class AnyrunFeedConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AnyrunFeed` connector.
    """

    api_key: SecretStr = Field(
        description="ANY.RUN TI Feeds API key. See 'Generate your API key' section in the README file.",
    )
    feed_fetch_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(minutes=int(x)),
    )
    feed_fetch_depth: int = Field(
        description="Feed fetch depth in days.",
        default=90,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `AnyrunFeedConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    anyrun: AnyrunFeedConfig = Field(default_factory=AnyrunFeedConfig)
