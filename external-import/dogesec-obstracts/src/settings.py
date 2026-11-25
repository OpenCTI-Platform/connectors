"""OpenCTI Obstracts connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ObstractsConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Obstracts connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="cdef318a-d5cf-4363-8ea3-b96aa360ab78",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Obstracts",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["obstracts"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class ObstractsConfig(BaseConfigModel):
    """Settings specific to the Obstracts connector."""

    base_url: HttpUrl = Field(
        description="The URL of the Obstracts API.",
        default=HttpUrl("https://api.obstracts.com/"),
    )
    api_key: SecretStr = Field(
        description="The Obstracts API key used to authenticate.",
    )
    feed_ids: ListFromString = Field(
        description=(
            "Comma-separated list of Obstracts feed IDs to import. "
            "When empty, every feed the team is subscribed to is imported."
        ),
        default=[],
    )
    days_to_backfill: int = Field(
        description=(
            "Number of days of posts to import for a feed that has not been "
            "imported yet. Recommended maximum: 365."
        ),
        default=7,
    )
    interval_hours: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda hours: timedelta(hours=int(hours)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Obstracts connector."""

    connector: ObstractsConnectorConfig = Field(
        default_factory=ObstractsConnectorConfig
    )
    obstracts: ObstractsConfig = Field(default_factory=ObstractsConfig)
