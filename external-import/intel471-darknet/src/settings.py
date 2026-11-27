"""OpenCTI Intel 471 Darknet connector settings module."""

import re
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr

RUN_EVERY_UNITS = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}


def run_every_to_timedelta(run_every: str) -> timedelta:
    """Convert a legacy `CONNECTOR_RUN_EVERY` value (e.g. '7d', '12h', '10m', '30s')."""
    match = re.fullmatch(r"(\d+)([dhms])", str(run_every).strip().lower())
    if match is None:
        raise ValueError(
            f"Invalid CONNECTOR_RUN_EVERY value '{run_every}': it SHOULD be a number "
            "followed by a unit among 'd', 'h', 'm', 's' (e.g. '7d', '12h', '10m', '30s')."
        )
    value, unit = match.groups()
    return timedelta(**{RUN_EVERY_UNITS[unit]: int(value)})


class Intel471DarknetConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Intel 471 Darknet connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5dbd8814-52af-46ee-a319-e2b98ceccef0",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Intel 471 Darknet",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["intel471-darknet"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=10),
    )
    run_every: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' instead.",
        new_namespaced_var="duration_period",
        new_value_factory=run_every_to_timedelta,
    )


class Intel471Config(BaseConfigModel):
    """Intel 471 API connection settings."""

    api_url: str = Field(
        description="Base URL of the Intel 471 REST API.",
        default="https://api.intel471.com/v1",
    )
    api_username: str = Field(
        description="Intel 471 API username (HTTP Basic authentication).",
    )
    api_key: SecretStr = Field(
        description="Intel 471 API key (HTTP Basic authentication password).",
    )


class Intel471DarknetConfig(BaseConfigModel):
    """Settings specific to the Intel 471 Darknet connector."""

    initial_history_alerts: int = Field(
        description=(
            "Unix epoch (seconds) of the earliest alert to import on the first run. "
            "Subsequent runs only fetch alerts newer than the previous successful run."
        ),
        default=0,
    )
    tlp: str = Field(
        description=(
            "TLP marking applied to every entity created by the connector. "
            "One of 'CLEAR', 'WHITE', 'GREEN', 'AMBER', 'AMBER_STRICT' "
            "(or 'AMBER+STRICT'), 'RED' (case-insensitive)."
        ),
        default="AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Intel 471 Darknet connector."""

    connector: Intel471DarknetConnectorConfig = Field(
        default_factory=Intel471DarknetConnectorConfig
    )
    intel471: Intel471Config = Field(default_factory=Intel471Config)
    intel471_darknet: Intel471DarknetConfig = Field(
        default_factory=Intel471DarknetConfig
    )
