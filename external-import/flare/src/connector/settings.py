from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="Flare",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Incident", "Observable", "Indicator"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(hours=1),
    )


class FlareConfig(BaseConfigModel):
    api_key: str = Field(
        description="Flare API key.",
    )
    api_base_url: str = Field(
        description="API base URL.",
        default="api.flare.io",
    )
    tenant_id: int | None = Field(
        description="Flare tenant ID.",
        default=None,
    )
    event_types: ListFromString = Field(
        description="Comma-separated list of Flare event types to import.",
        default=["stealer_log", "domain", "ransomleak", "leak"],
    )
    event_actions: ListFromString = Field(
        description="Comma-separated list of event actions to filter by. If not set, all actions are imported.",
        default=[],
    )
    lookback_days: int = Field(
        description="Number of days to look back on the first run.",
        default=30,
    )
    tlp_level: Literal[
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="white",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    flare: FlareConfig = Field(default_factory=FlareConfig)
