"""Connector configuration.

`ExternalImportConnectorConfig` holds the options every EXTERNAL_IMPORT
connector has, with defaults for this connector; `SplunkSavedSearchesConfig`
the options specific to Splunk. Values come from environment variables
(`SPLUNK_SAVED_SEARCHES_*`) or `config.yml`.
"""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="The unique identifier of the connector.",
        default="665a092c-a049-4e5b-a130-5eb34dee8338",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Splunk Saved Searches",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=["Indicator", "Attack-Pattern", "SecurityPlatform"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, as an ISO 8601 "
        "duration (e.g. `PT6H` for six hours). Every run reads the full rule set.",
        default=timedelta(hours=6),
    )


class SplunkSavedSearchesConfig(BaseConfigModel):
    """Options specific to the Splunk saved searches connector."""

    api_url: HttpUrl = Field(
        description="Base URL of the Splunk REST API (management port), "
        "e.g. `https://splunk.example.com:8089`.",
    )
    token: SecretStr = Field(
        description="Splunk authentication token, sent as `Authorization: Bearer "
        "<token>`. Its user needs read access to the saved searches of the selected "
        "apps.",
    )
    app: str = Field(
        description="App namespace to read saved searches from. `-` reads every app.",
        default="-",
        min_length=1,
    )
    owner: str = Field(
        description="Owner namespace to read saved searches from. `-` reads every owner.",
        default="-",
        min_length=1,
    )
    search_scope: Literal["correlation_searches", "alerts", "all"] = Field(
        description="Saved searches to import: `correlation_searches` (Enterprise "
        "Security correlation searches only), `alerts` (correlation searches and "
        "scheduled searches that trigger alert actions) or `all`.",
        default="alerts",
    )
    web_url: HttpUrl | None = Field(
        description="Base URL of Splunk Web, e.g. `https://splunk.example.com:8000`. "
        "When set, each Indicator links to its saved search.",
        default=None,
    )
    import_disabled_rules: bool = Field(
        description="Import disabled saved searches too, with the deployment status "
        "`deployed` (enabled ones get `active`). When false, disabled saved searches "
        "are left out and count as removed.",
        default=True,
    )
    page_size: int = Field(
        description="Saved searches requested per page (`count`).",
        default=100,
        ge=1,
        le=10000,
    )
    request_timeout: int = Field(
        description="Timeout of each HTTP request, in seconds.",
        default=60,
        ge=1,
    )
    max_retries: int = Field(
        description="Retries of a request failing with a rate limit (429), a server "
        "error (5xx) or a network error, with exponential backoff.",
        default=5,
        ge=0,
    )
    verify_ssl: bool = Field(
        description="Verify the TLS certificate of the Splunk REST API.",
        default=True,
    )
    platform_name: str = Field(
        description="Name of the Security Platform the rules are deployed on in OpenCTI.",
        default="Splunk",
        min_length=1,
    )
    platform_type: Literal["SIEM", "EDR", "XDR", "SOAR", "NDR", "ISPM"] = Field(
        description="Type of that Security Platform (`security_platform_type`).",
        default="SIEM",
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates.",
        default=TLPLevel.AMBER,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    splunk_saved_searches: SplunkSavedSearchesConfig = Field(
        default_factory=SplunkSavedSearchesConfig
    )
