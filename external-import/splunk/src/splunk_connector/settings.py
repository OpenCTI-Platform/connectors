"""OpenCTI Splunk connector settings."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, PositiveInt, SecretStr, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """External import connector defaults."""

    name: str = Field(default="Splunk", description="The connector name.")
    scope: ListFromString = Field(
        default=["indicator", "identity", "incident"],
        description="OpenCTI entity scopes imported by the connector.",
    )
    duration_period: timedelta = Field(
        default=timedelta(minutes=5),
        description="Base scheduler period. Dataset intervals are checked on each tick.",
    )


class SplunkConfig(BaseConfigModel):
    """Splunk-specific connector configuration."""

    base_url: HttpUrl = Field(description="Splunk management API base URL.")
    token: SecretStr = Field(description="Splunk bearer token.")
    verify_ssl: bool = Field(default=True, description="Verify Splunk TLS certificates.")
    timeout_seconds: PositiveInt = Field(default=60, description="HTTP timeout in seconds.")
    owner: str = Field(default="-", description="Splunk namespace owner.")
    app: str = Field(default="-", description="Splunk namespace app.")

    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = Field(
        default="amber",
        description="Default TLP marking for imported objects.",
    )
    confidence: int = Field(default=60, ge=0, le=100, description="Default confidence.")
    batch_size: PositiveInt = Field(default=500, description="STIX objects per bundle.")
    max_records_per_run: int = Field(
        default=10000,
        description="Maximum source records per dataset run. Use 0 to disable the cap.",
    )

    scopes: ListFromString = Field(
        default=["indicator", "identity", "incident"],
        description="Entity scopes to expose: indicator, identity, incident.",
    )
    import_indicators: bool = Field(default=True, description="Import saved searches.")
    import_identities: bool = Field(default=True, description="Import assets and identities.")
    import_incidents: bool = Field(default=True, description="Import findings and alerts.")

    indicators_interval: timedelta = Field(
        default=timedelta(hours=1),
        description="Interval between saved-search imports.",
    )
    identities_interval: timedelta = Field(
        default=timedelta(days=1),
        description="Interval between asset/identity imports.",
    )
    incidents_interval: timedelta = Field(
        default=timedelta(minutes=15),
        description="Interval between finding/alert imports.",
    )
    incidents_lookback: timedelta = Field(
        default=timedelta(days=1),
        description="Initial lookback window for incidents.",
    )

    indicators_search: str | None = Field(
        default=None,
        description="Optional custom SPL search for saved-search inventory.",
    )
    identities_search: str | None = Field(
        default=None,
        description="Optional custom SPL search for assets and identities.",
    )
    incidents_search: str | None = Field(
        default=None,
        description="Optional custom SPL search for findings and alerts.",
    )
    include_disabled: bool = Field(
        default=False,
        description="Include disabled saved searches when importing indicators.",
    )
    note_type_search_parameters: str = Field(
        default="Search Parameters",
        description="Note type for saved-search parameter notes.",
    )
    es_api_prefix: str = Field(
        default="/servicesNS/nobody/missioncontrol/public/v2",
        description="Splunk Enterprise Security public API prefix.",
    )

    @field_validator("scopes", mode="after")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        allowed = {"indicator", "identity", "incident"}
        invalid = sorted(set(value) - allowed)
        if invalid:
            raise ValueError(f"Unsupported scope(s): {', '.join(invalid)}")
        return value

    @field_validator("tlp_level", mode="before")
    @classmethod
    def lowercase_tlp(cls, value: str) -> str:
        return value.lower()

    @field_validator(
        "indicators_search",
        "identities_search",
        "incidents_search",
        mode="before",
    )
    @classmethod
    def empty_string_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class ConnectorSettings(BaseConnectorSettings):
    """Connector settings root."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
