from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


def _minutes_to_duration(value: object) -> timedelta:
    minutes = int(value)
    if minutes <= 0:
        raise ValueError("interval_minutes must be a positive integer")
    return timedelta(minutes=minutes)


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

    @field_validator("duration_period")
    @classmethod
    def validate_duration_period(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0):
            raise ValueError("duration_period must be a positive duration")
        return value


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

    @field_validator("initial_lookback_days")
    @classmethod
    def validate_initial_lookback_days(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("initial_lookback_days must be a positive integer")
        return value


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig,
    )
    trukno: TruKnoConfig = Field(default_factory=TruKnoConfig)
