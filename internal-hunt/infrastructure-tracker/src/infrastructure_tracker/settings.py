"""Configuration of the infrastructure tracker hunt connector."""

from typing import Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class InfrastructureTrackerConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the infrastructure tracker."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9e4b7c2a-5f1d-4e83-a6b0-2c8d7f3e1a95",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Infrastructure Tracker",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["internet"],
    )


def _secret(value: SecretStr | None) -> str:
    """Return the stripped value of an optional secret."""
    return value.get_secret_value().strip() if value else ""


class InfrastructureTrackerConfig(BaseConfigModel):
    """Internet scanning sources of the infrastructure tracker."""

    censys_token: SecretStr | None = Field(
        description="Censys Platform personal access token. Leave empty to disable Censys.",
        default=None,
    )
    censys_organisation_id: str | None = Field(
        description="Censys organization ID (required by paid Censys Platform accounts).",
        default=None,
    )
    censys_api_url: HttpUrl = Field(
        description="URL of the Censys Platform API.",
        default=HttpUrl("https://api.platform.censys.io"),
    )
    silentpush_api_key: SecretStr | None = Field(
        description="Silent Push API key. Leave empty to disable Silent Push.",
        default=None,
    )
    silentpush_api_url: HttpUrl = Field(
        description="URL of the Silent Push API.",
        default=HttpUrl("https://api.silentpush.com"),
    )
    urlscan_api_key: SecretStr | None = Field(
        description="urlscan.io API key. Leave empty to disable urlscan.io.",
        default=None,
    )
    urlscan_api_url: HttpUrl = Field(
        description="URL of the urlscan.io API.",
        default=HttpUrl("https://urlscan.io"),
    )
    cymru_scout_api_key: SecretStr | None = Field(
        description="Team Cymru Scout API key. Leave empty to disable Team Cymru Scout.",
        default=None,
    )
    cymru_scout_api_url: HttpUrl = Field(
        description="URL of the Team Cymru Scout API.",
        default=HttpUrl("https://scout.cymru.com/api/scout"),
    )
    internetdb_enabled: bool = Field(
        description="Whether to enrich the IP addresses found with Shodan InternetDB (host names, ports, "
        "tags; no API key needed).",
        default=True,
    )
    internetdb_url: HttpUrl = Field(
        description="URL of Shodan InternetDB.",
        default=HttpUrl("https://internetdb.shodan.io"),
    )
    internetdb_max_lookups: int = Field(
        description="Maximum number of IP addresses enriched with Shodan InternetDB per hunt run.",
        default=25,
        ge=0,
        le=1000,
    )
    create_certificates: bool = Field(
        description="Whether to create the X.509 certificates found (with their indicators).",
        default=True,
    )

    @model_validator(mode="after")
    def _check_sources(self) -> Self:
        """Require at least one internet search source."""
        if not self.sources:
            raise ValueError(
                "Configure at least one search source: censys_token, silentpush_api_key, "
                "urlscan_api_key or cymru_scout_api_key."
            )
        return self

    @property
    def sources(self) -> list[str]:
        """Return the search sources with credentials, in query order."""
        keys = {
            "censys": _secret(self.censys_token),
            "silentpush": _secret(self.silentpush_api_key),
            "urlscan": _secret(self.urlscan_api_key),
            "cymru_scout": _secret(self.cymru_scout_api_key),
        }
        return [source for source, key in keys.items() if key]


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the infrastructure tracker hunt connector."""

    connector: InfrastructureTrackerConnectorConfig = Field(
        default_factory=InfrastructureTrackerConnectorConfig
    )
    infrastructure_tracker: InfrastructureTrackerConfig = Field(
        default_factory=InfrastructureTrackerConfig
    )
