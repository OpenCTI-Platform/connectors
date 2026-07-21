"""Settings for the Google SecOps external-import connector."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from google_secops_siem_incidents.utils.enums import Priority, Severity
from pydantic import Field, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Override BaseExternalImportConnectorConfig with Google SecOps defaults."""

    name: str = Field(
        "Google SecOps",
        description="The name of the connector.",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )
    scope: ListFromString = Field(
        ["google-secops-siem-incidents"],
        description="The scope of the connector, e.g. 'flashpoint'.",
    )


class GoogleSecOpsConfig(BaseConfigModel):
    """Configuration specific to the Google SecOps connector."""

    base_url: str = Field(
        "https://chronicle.googleapis.com",
        description="API base URL (region prefix added at runtime).",
    )
    project_id: str = Field(description="GCP project ID.")
    project_region: str = Field(description="Region (e.g. 'us', 'eu', 'asia').")
    project_instance: str = Field(description="Instance UUID.")
    private_key: str = Field(description="Service account private key (PEM).")
    private_key_id: str = Field(description="Service account private key ID.")

    client_email: str = Field(description="Service account client email.")
    client_id: str = Field(description="Service account client ID.")
    auth_uri: str = Field(
        "https://accounts.google.com/o/oauth2/auth",
        description="OAuth2 auth URI.",
    )
    token_uri: str = Field(
        "https://oauth2.googleapis.com/token",
        description="OAuth2 token URI.",
    )
    auth_provider_cert: str = Field(
        "https://www.googleapis.com/oauth2/v1/certs",
        description="OAuth2 auth provider cert URL.",
    )
    client_cert_url: str = Field(description="Service account client cert URL.")
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        "amber",
        description="Default TLP level of the imported entities.",
    )
    first_start_time: timedelta = Field(
        timedelta(days=1),
        description=(
            "How far back to fetch alerts on the very first run "
            "(ISO-8601 duration, e.g. P1D). Used only when no prior state exists."
        ),
    )
    severity_filter: Severity | None = Field(
        None,
        description=(
            "Minimum severity level to import. All alerts at or above this "
            "level are imported (CRITICAL > HIGH > MEDIUM > LOW > INFO). "
            "When not set, all severities are imported. "
            "Alerts with unknown severity are always imported."
        ),
    )
    priority_filter: Priority | None = Field(
        None,
        description=(
            "Minimum priority level to import. All alerts at or above this "
            "level are imported (CRITICAL > HIGH > MEDIUM > LOW > INFO). "
            "When not set, all priorities are imported. "
            "Alerts with unknown priority are always imported."
        ),
    )
    risk_score_filter: int | None = Field(
        None,
        ge=0,
        description=(
            "Minimum risk score to import. All alerts with a risk score "
            "greater than or equal to this value are imported. "
            "Alerts without a risk score always pass. "
            "When not set, all alerts are imported regardless of risk score."
        ),
    )
    tags_include: ListFromString = Field(
        default=[],
        description=(
            "Comma-separated list of tags to include. Only alerts that have "
            "at least one of these tags are imported. "
            "When empty, no inclusion filter is applied."
        ),
    )
    tags_exclude: ListFromString = Field(
        default=[],
        description=(
            "Comma-separated list of tags to exclude. Alerts that have "
            "any of these tags are excluded. "
            "When empty, no exclusion filter is applied."
        ),
    )

    @field_validator("tags_include", "tags_exclude", mode="after")
    @classmethod
    def _normalize_tags(cls, v: list[str]) -> list[str]:
        """Normalize tag values to lowercase for case-insensitive matching."""
        return [t.strip().lower() for t in v if t.strip()]

    @field_validator("private_key", mode="before")
    @classmethod
    def _normalize_pem_newlines(cls, v: str) -> str:
        r"""Replace literal '\\n' with real newlines so PEM parsing succeeds."""
        if isinstance(v, str) and "\\n" in v:
            return v.replace("\\n", "\n")
        return v


class ConnectorSettings(BaseConnectorSettings):
    """Override BaseConnectorSettings for the Google SecOps connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    google_secops_siem_incidents: GoogleSecOpsConfig = Field(
        default_factory=GoogleSecOpsConfig
    )
