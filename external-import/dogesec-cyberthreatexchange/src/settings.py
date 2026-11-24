"""OpenCTI Cyber Threat Exchange connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class CyberThreatExchangeConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Cyber Threat Exchange connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="b51736f7-7ed8-4c41-b247-eadd836f4f6c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CyberThreatExchange",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["cyberthreatexchange"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CyberThreatExchangeConfig(BaseConfigModel):
    """Settings specific to the Cyber Threat Exchange connector."""

    base_url: HttpUrl = Field(
        description="The base URL of the Cyber Threat Exchange API.",
        default=HttpUrl("https://api.cyberthreatexchange.com/"),
    )
    api_key: SecretStr = Field(
        description="The API key used to authenticate to the Cyber Threat Exchange API.",
    )
    feed_ids: ListFromString = Field(
        description=(
            "Comma-separated list of the IDs of the subscribed feeds to import "
            "(e.g. 'f0895eb3-7d90-4b45-8664-a7e157ba880f,b63c638e-43e6-43d4-bfac-5b71c264b132'). "
            "At least one feed ID is required: the connector stops at startup otherwise."
        ),
        default=[],
    )
    interval_hours: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda hours: timedelta(hours=int(hours)),
        description="The polling interval, in hours.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Cyber Threat Exchange connector."""

    connector: CyberThreatExchangeConnectorConfig = Field(
        default_factory=CyberThreatExchangeConnectorConfig
    )
    cyberthreatexchange: CyberThreatExchangeConfig = Field(
        default_factory=CyberThreatExchangeConfig
    )
