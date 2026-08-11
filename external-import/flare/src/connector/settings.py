from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator

SEVERITIES = ("info", "low", "medium", "high", "critical")


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="Flare",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4ca16691-f5e3-46a2-828e-a29549a8b61f",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Flare"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(hours=1),
    )


class FlareConfig(BaseConfigModel):
    api_key: SecretStr = Field(
        description="Flare API key.",
    )

    api_base_url: str = DeprecatedField(
        deprecated="Use api_domain instead",
        new_namespaced_var="api_domain",
        removal_date="2027-06-30",  # Optional informative removal deadline
    )

    api_domain: str = Field(
        description="API domain name.",
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
    severities: ListFromString = Field(
        description="Comma-separated list of severities to filter by: 'info', 'low', 'medium', 'high', 'critical'. If not set, all severities are imported.",
        default=[],
    )
    lookback_days: int = Field(
        description="Number of days to look back on the first run.",
        default=30,
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="white",
    )

    @field_validator("severities")
    @classmethod
    def validate_severities(cls, value: list[str]) -> list[str]:
        unknown = [severity for severity in value if severity not in SEVERITIES]
        if unknown:
            raise ValueError(
                f"Unknown severities {unknown}. Available values: {', '.join(SEVERITIES)}."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    flare: FlareConfig = Field(default_factory=FlareConfig)
