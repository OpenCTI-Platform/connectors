import re
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
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or (isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value.strip()))
    ):
        raise ValueError("interval_minutes must be a positive integer")
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
        gt=timedelta(0),
    )


class TruKnoConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="TruKno API base URL.",
        default="https://api.trukno.com/v2",
    )
    api_key: SecretStr = Field(description="TruKno API key.")
    initial_lookback: timedelta = Field(
        description="The period of time to look back on the first run.",
        default=timedelta(days=30),
        gt=timedelta(0),
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
