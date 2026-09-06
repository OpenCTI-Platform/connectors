import os
import re
from datetime import timedelta
from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ConfigValidationError,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator

LEGACY_CONFIG_MESSAGE = (
    "TRUKNO_CONNECTOR_CONFIG is no longer supported. Unset it and move configuration "
    "to the connector-root config.yml (see config.yml.sample), or use environment variables."
)


class LegacyConfigPathError(ConfigValidationError):
    """The removed configuration-path override is still configured."""


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
    )

    @model_validator(mode="before")
    @classmethod
    def apply_defaults_to_blank_optional_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = data.copy()
            for field_name in (
                "name",
                "scope",
                "type",
                "log_level",
                "duration_period",
            ):
                if data.get(field_name) == "":
                    data.pop(field_name)
        return data

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

    @model_validator(mode="before")
    @classmethod
    def apply_defaults_to_blank_optional_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = data.copy()
            for field_name in ("api_base_url", "initial_lookback_days"):
                if data.get(field_name) == "":
                    data.pop(field_name)
        return data

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

    def __init__(self) -> None:
        # Reject the override before the SDK loads any configuration or secrets.
        if os.environ.get("TRUKNO_CONNECTOR_CONFIG"):
            raise LegacyConfigPathError(LEGACY_CONFIG_MESSAGE)
        super().__init__()

    @classmethod
    def _migrate_deprecated_variables(cls, data: dict[str, Any]) -> dict[str, Any]:
        trukno = data.get("trukno", {})
        connector = data.get("connector", {})
        if (
            isinstance(trukno, dict)
            and "interval_minutes" in trukno
            and isinstance(connector, dict)
            and "duration_period" in connector
        ):
            _minutes_to_duration(trukno["interval_minutes"])
        return super()._migrate_deprecated_variables(data)
