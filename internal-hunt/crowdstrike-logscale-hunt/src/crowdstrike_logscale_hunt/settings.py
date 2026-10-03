"""Configuration of the CrowdStrike LogScale hunt connector."""

from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class CrowdstrikeLogscaleHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the CrowdStrike LogScale hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="8b3e5f20-9c4d-4a7e-b6f1-0d2c7a9e4b18",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CrowdStrike LogScale Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["crowdstrike-logscale"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="CrowdStrike Falcon",
    )


def _filled(value: SecretStr | str | None) -> bool:
    """Return True when a setting holds a non-blank value."""
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    return bool(value and value.strip())


class CrowdstrikeLogscaleHuntConfig(BaseConfigModel):
    """CrowdStrike Falcon Next-Gen SIEM and LogScale settings of the hunt connector."""

    deployment: Literal["falcon", "logscale"] = Field(
        description="'falcon' queries Falcon Next-Gen SIEM through the CrowdStrike API (OAuth2 client "
        "credentials); 'logscale' queries a LogScale cluster (self-hosted or LogScale Cloud) with an "
        "API token.",
        default="falcon",
    )
    base_url: HttpUrl = Field(
        description="CrowdStrike API URL of the Falcon cloud: 'https://api.crowdstrike.com' (US-1), "
        "'https://api.us-2.crowdstrike.com', 'https://api.eu-1.crowdstrike.com' or "
        "'https://api.laggar.gcw.crowdstrike.com' (GOV).",
        default=HttpUrl("https://api.crowdstrike.com"),
    )
    client_id: str | None = Field(
        description="CrowdStrike API client ID (deployment 'falcon').",
        default=None,
    )
    client_secret: SecretStr | None = Field(
        description="CrowdStrike API client secret (deployment 'falcon').",
        default=None,
    )
    logscale_url: HttpUrl | None = Field(
        description="URL of the LogScale cluster, e.g. 'https://cloud.us.humio.com' (deployment 'logscale').",
        default=None,
    )
    logscale_token: SecretStr | None = Field(
        description="LogScale API token with the search permission on the repository "
        "(deployment 'logscale').",
        default=None,
    )
    repository: str = Field(
        description="Repository or view the hunts search: 'search-all' (all Falcon and third-party "
        "data), 'investigate_view', 'third-party', or a LogScale repository name.",
        default="search-all",
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TLS certificate of the API.",
        default=True,
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': "
        "'crowdstrike_falcon' (Falcon telemetry), 'crowdstrike_fdr' (Falcon Data Replicator events) "
        "or 'none'.",
        default="crowdstrike_falcon",
    )
    poll_interval: float = Field(
        description="Seconds between two status checks of a query job, when LogScale gives no hint.",
        default=1.0,
        gt=0,
    )

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require the credentials of the configured deployment."""
        if self.deployment == "falcon":
            missing = [
                name
                for name, value in (
                    ("client_id", self.client_id),
                    ("client_secret", self.client_secret),
                )
                if not _filled(value)
            ]
        else:
            missing = [
                name
                for name, value in (
                    ("logscale_url", str(self.logscale_url or "")),
                    ("logscale_token", self.logscale_token),
                )
                if not _filled(value)
            ]
        if missing:
            raise ValueError(
                f"deployment is '{self.deployment}' but {', '.join(missing)} is not set."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the CrowdStrike LogScale hunt connector."""

    connector: CrowdstrikeLogscaleHuntConnectorConfig = Field(
        default_factory=CrowdstrikeLogscaleHuntConnectorConfig
    )
    crowdstrike_logscale_hunt: CrowdstrikeLogscaleHuntConfig = Field(
        default_factory=CrowdstrikeLogscaleHuntConfig
    )
