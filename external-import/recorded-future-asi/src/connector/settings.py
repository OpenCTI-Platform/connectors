from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr, model_validator

ExposureSeverity = Literal["unknown", "informational", "moderate", "critical"]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Recorded Future ASI Exposures",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "incident",
            "vulnerability",
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class RecordedFutureAsiConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RecordedFutureAsiConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="API base URL.",
        default="https://api.securitytrails.com/v2",
    )
    api_v1_base_url: HttpUrl = Field(
        description="v1 API base URL for exposure history activity.",
        default="https://api.securitytrails.com/v1",
    )
    api_key: SecretStr = Field(description="API key for authentication.")
    project_id: str = Field(description="ASI project ID to fetch exposures from.")
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="amber+strict",
    )
    portal_base_url: HttpUrl | None = Field(
        description="Optional portal base URL for external reference deep links.",
        default=None,
    )
    page_limit: int = Field(
        description="Number of exposures to fetch per API page.",
        default=100,
        ge=1,
        le=1000,
    )
    run_limit: int | None = Field(
        description="Max exposures to import per connector run. None = no limit (current behavior).",
        default=None,
        ge=1,
    )
    retry_max_attempts: int = Field(
        description="Maximum HTTP request attempts (including the first) before giving up.",
        default=3,
        ge=1,
        le=10,
    )
    retry_initial_seconds: float = Field(
        description="Initial backoff delay in seconds for retried requests.",
        default=1,
        ge=0.1,
        le=30,
    )
    retry_max_seconds: float = Field(
        description="Maximum backoff delay in seconds between retry attempts.",
        default=60,
        ge=1,
        le=300,
    )
    filter_severity_min: ExposureSeverity | None = Field(
        description="Only import exposures at or above this severity.",
        default=None,
    )
    filter_severity_exact: ExposureSeverity | None = Field(
        description="Only import exposures matching this severity exactly.",
        default=None,
    )

    @model_validator(mode="after")
    def validate_severity_filters(self) -> "RecordedFutureAsiConfig":
        if self.filter_severity_min and self.filter_severity_exact:
            raise ValueError(
                "Only one of filter_severity_min or filter_severity_exact may be set."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RecordedFutureAsiConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    recorded_future_asi: RecordedFutureAsiConfig = Field(
        default_factory=RecordedFutureAsiConfig,
        validation_alias=AliasChoices("recorded_future_asi", "recorded-future-asi"),
    )
