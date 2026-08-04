from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, PositiveInt, SecretStr, model_validator


def _run_every_to_duration_period(run_every: str) -> timedelta:
    unit_run_every = run_every[-1:]
    value = int(run_every[:-1])
    if unit_run_every == "d":
        return timedelta(days=value)
    if unit_run_every == "h":
        return timedelta(hours=value)
    if unit_run_every == "m":
        return timedelta(minutes=value)
    if unit_run_every == "s":
        return timedelta(seconds=value)
    raise ValueError(f"Invalid value for CONNECTOR_RUN_EVERY: {run_every}")


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        default="ransomwarelive--51402e18-8b2a-4012-bec2-adaa2f41bd59",
        description="A UUID v4 to identify this connector instance.",
    )
    name: str = Field(
        default="Ransomware Connector",
        description="The connector name displayed in OpenCTI.",
    )
    scope: ListFromString = Field(
        default=[
            "identity",
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
            "report",
        ],
        description="Comma-separated STIX entity scope for this connector.",
    )
    duration_period: timedelta = Field(
        default=timedelta(minutes=10),
        description="Duration between two scheduled runs of the connector.",
    )

    # Deprecated fields for backward compatibility
    run_every: str | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' instead.",
        new_namespaced_var="duration_period",
        new_value_factory=_run_every_to_duration_period,
    )
    pull_history: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_PULL_HISTORY' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="pull_history",
    )
    history_start_year: PositiveInt | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_HISTORY_START_YEAR' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="history_start_year",
    )
    create_threat_actor: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_THREAT_ACTOR' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_threat_actor",
    )
    create_intrusion_set: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_INTRUSION_SET' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_intrusion_set",
    )
    create_campaign: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_CAMPAIGN' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_campaign",
    )
    create_report: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_REPORT' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_report",
    )
    create_leak_site_domains: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_LEAK_SITE_DOMAINS' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_leak_site_domains",
    )
    create_leak_post_refs: bool | None = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_CREATE_LEAK_POST_REFS' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="create_leak_post_refs",
    )
    marking_value: (
        Literal[
            "TLP:CLEAR",
            "TLP:WHITE",
            "TLP:GREEN",
            "TLP:AMBER",
            "TLP:AMBER+STRICT",
            "TLP:RED",
        ]
        | None
    ) = DeprecatedField(
        default=None,
        deprecated="Use 'RANSOMWARELIVE_MARKING_VALUE' instead.",
        new_namespace="ransomwarelive",
        new_namespaced_var="marking_value",
    )


class RansomwareliveConfig(BaseConfigModel):
    api_base_url: Literal[
        "https://api.ransomware.live/v2",
        "https://api-pro.ransomware.live",
    ] = Field(
        default="https://api.ransomware.live/v2",
        description="Ransomware.live API base URL.",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="API key sent in `X-API-KEY` header (required for Ransomware.live API PRO use only).",
    )
    pull_history: bool = Field(
        default=False,
        description=(
            "Whether to pull historic data. It is not recommended to set it "
            "to `true` as there will be a large influx of data."
        ),
    )
    history_start_year: PositiveInt = Field(
        default=2023,
        description=(
            "Year (or YYYYMM) to start historical backfill from. "
            "Values older than `2020` are clamped to `2020-01` at runtime."
        ),
    )
    create_threat_actor: bool = Field(
        default=False,
        description="Whether to create a Threat Actor object.",
    )
    create_intrusion_set: bool = Field(
        default=True,
        description="Whether to create an Intrusion Set object.",
    )
    create_campaign: bool = Field(
        default=False,
        description="Whether to create a Campaign object.",
    )
    create_report: bool = Field(
        default=True,
        description="Whether to create a Report object.",
    )
    create_leak_site_domains: bool = Field(
        default=False,
        description=(
            "Whether to create DomainName observables for ransomware group leak "
            "sites and link them to the IntrusionSet."
        ),
    )
    create_leak_post_refs: bool = Field(
        default=False,
        description="Whether to include the leak post URL as a report external reference.",
    )
    marking_value: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:CLEAR",
        description="TLP marking attached to every emitted STIX object.",
    )

    @model_validator(mode="before")
    @classmethod
    def validate_api_key(cls, data: dict) -> dict:
        api_base_url = data.get("api_base_url")
        api_key = data.get("api_key") or ""

        if api_base_url == "https://api-pro.ransomware.live":
            if not api_key.strip():
                raise ValueError(
                    "`RANSOMWARELIVE_API_KEY` is required when `RANSOMWARELIVE_API_BASE_URL` is 'https://api-pro.ransomware.live'."
                )
        else:
            data["api_key"] = None  # discard API key if not using API-PRO

        return data


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ransomwarelive: RansomwareliveConfig = Field(default_factory=RansomwareliveConfig)

    @model_validator(mode="after")
    def validate_duration_period(self):
        if self.connector.duration_period < timedelta(minutes=1):
            raise ValueError("CONNECTOR_DURATION_PERIOD must at least 1 minute")
        return self
