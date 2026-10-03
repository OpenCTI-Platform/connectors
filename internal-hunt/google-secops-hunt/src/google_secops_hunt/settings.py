"""Configuration of the Google SecOps hunt connector."""

from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class GoogleSecopsHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Google SecOps hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="2e6a9d14-7f3b-4c85-a1d0-5b8e3c7f9a26",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Google SecOps Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["google-secops"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Google SecOps",
    )


class GoogleSecopsHuntConfig(BaseConfigModel):
    """Google SecOps (Chronicle) settings of the hunt connector."""

    base_url: HttpUrl = Field(
        description="Chronicle API URL; the region is prefixed to the host at runtime.",
        default=HttpUrl("https://chronicle.googleapis.com"),
    )
    project_id: str = Field(
        description="Google Cloud project ID of the SecOps instance."
    )
    project_region: str = Field(
        description="Region of the SecOps instance, e.g. 'us', 'europe' or 'asia-southeast1'.",
    )
    project_instance: str = Field(description="Customer ID (instance UUID) of SecOps.")
    private_key: SecretStr = Field(description="Service account private key (PEM).")
    private_key_id: str = Field(description="Service account private key ID.")
    client_email: str = Field(description="Service account client email.")
    client_id: str = Field(description="Service account client ID.")
    auth_uri: str = Field(
        description="OAuth2 auth URI of the service account.",
        default="https://accounts.google.com/o/oauth2/auth",
    )
    token_uri: str = Field(
        description="OAuth2 token URI of the service account.",
        default="https://oauth2.googleapis.com/token",
    )
    auth_provider_cert: str = Field(
        description="OAuth2 auth provider certificates URL of the service account.",
        default="https://www.googleapis.com/oauth2/v1/certs",
    )
    client_cert_url: str = Field(
        description="Client certificate URL of the service account.",
        default="",
    )
    query_language: Literal["udm", "yara-l"] = Field(
        description="Language Sigma rules are translated into: 'udm' (UDM search, returns the "
        "matching events) or 'yara-l' (YARA-L 2.0 rule tested over the run window, returns "
        "detections).",
        default="udm",
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': 'secops_udm' or 'none'.",
        default="secops_udm",
    )

    @field_validator("private_key", mode="before")
    @classmethod
    def _normalize_pem_newlines(cls, value: Any) -> Any:
        r"""Replace literal '\n' sequences with newlines so that the PEM key parses."""
        if isinstance(value, str) and "\\n" in value:
            return value.replace("\\n", "\n")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Google SecOps hunt connector."""

    connector: GoogleSecopsHuntConnectorConfig = Field(
        default_factory=GoogleSecopsHuntConnectorConfig
    )
    google_secops_hunt: GoogleSecopsHuntConfig = Field(
        default_factory=GoogleSecopsHuntConfig
    )
