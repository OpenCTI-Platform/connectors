from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


def _minutes_to_duration(value: object) -> timedelta:
    return timedelta(minutes=int(value))


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="TruKno",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["report", "attack-pattern", "malware"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(hours=1),
    )


class TruKnoConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="TruKno API base URL.",
        default="https://api.trukno.com/v2",
    )
    api_key: SecretStr = Field(description="TruKno API key.")
    initial_lookback_days: int = Field(
        description="Number of days to look back on the first run.",
        default=30,
    )
    interval_minutes: int | None = DeprecatedField(
        deprecated="Use CONNECTOR_DURATION_PERIOD instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=_minutes_to_duration,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig,
    )
    trukno: TruKnoConfig = Field(default_factory=TruKnoConfig)
