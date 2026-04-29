"""Settings for the Google SecOps external-import connector."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field


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


class GoogleSecOpsConfig(BaseConfigModel):
    """Configuration specific to the Google SecOps Chronicle connector."""

    chronicle_base_url: str = Field(
        "https://chronicle.googleapis.com",
        description="Chronicle API base URL (region prefix added at runtime).",
    )
    chronicle_project_id: str = Field(description="GCP project ID.")
    chronicle_project_region: str = Field(
        description="Chronicle region (e.g. 'us', 'eu', 'asia')."
    )
    chronicle_project_instance: str = Field(description="Chronicle instance UUID.")
    chronicle_private_key: str = Field(description="Service account private key (PEM).")
    chronicle_private_key_id: str = Field(description="Service account private key ID.")
    chronicle_client_email: str = Field(description="Service account client email.")
    chronicle_client_id: str = Field(description="Service account client ID.")
    chronicle_auth_uri: str = Field(
        "https://accounts.google.com/o/oauth2/auth",
        description="OAuth2 auth URI.",
    )
    chronicle_token_uri: str = Field(
        "https://oauth2.googleapis.com/token",
        description="OAuth2 token URI.",
    )
    chronicle_auth_provider_cert: str = Field(
        "https://www.googleapis.com/oauth2/v1/certs",
        description="OAuth2 auth provider cert URL.",
    )
    chronicle_client_cert_url: str = Field(
        description="Service account client cert URL."
    )
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


class ConnectorSettings(BaseConnectorSettings):
    """Override BaseConnectorSettings for the Google SecOps connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    google_secops_siem_incidents: GoogleSecOpsConfig = Field(
        default_factory=GoogleSecOpsConfig
    )
