"""Connector configuration.

`ExternalImportConnectorConfig` holds the options every EXTERNAL_IMPORT
connector has, with defaults for this connector; `SentinelAnalyticsRulesConfig`
the options specific to Microsoft Sentinel. Values come from environment
variables (`SENTINEL_ANALYTICS_RULES_*`) or `config.yml`.
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
        default="df4889a5-031d-4981-9846-1d5150ada087",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Microsoft Sentinel Analytics Rules",
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


class SentinelAnalyticsRulesConfig(BaseConfigModel):
    """Options specific to the Microsoft Sentinel analytics rules connector."""

    tenant_id: str = Field(
        description="Microsoft Entra ID tenant of the application.",
        min_length=1,
    )
    client_id: str = Field(
        description="Application (client) id of the Entra ID app registration.",
        min_length=1,
    )
    client_secret: SecretStr = Field(
        description="Client secret of the app registration. The application needs "
        "the `Microsoft Sentinel Reader` role on the workspace (or its resource group).",
    )
    subscription_id: str = Field(
        description="Azure subscription holding the Log Analytics workspace.",
        min_length=1,
    )
    resource_group: str = Field(
        description="Resource group of the Log Analytics workspace.",
        min_length=1,
    )
    workspace_name: str = Field(
        description="Name of the Log Analytics workspace Microsoft Sentinel runs on.",
        min_length=1,
    )
    management_url: HttpUrl = Field(
        description="Azure Resource Manager endpoint. Change it for sovereign clouds "
        "(e.g. `https://management.usgovcloudapi.net`).",
        default=HttpUrl("https://management.azure.com"),
    )
    login_url: HttpUrl = Field(
        description="Microsoft Entra ID authority. Change it for sovereign clouds "
        "(e.g. `https://login.microsoftonline.us`).",
        default=HttpUrl("https://login.microsoftonline.com"),
    )
    api_version: str = Field(
        description="Microsoft.SecurityInsights API version. The default one returns "
        "NRT rules and sub-techniques.",
        default="2025-07-01-preview",
        min_length=1,
    )
    import_disabled_rules: bool = Field(
        description="Import disabled rules too, with the deployment status `deployed` "
        "(enabled rules get `active`). When false, disabled rules are left out and "
        "count as removed.",
        default=True,
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
    platform_name: str = Field(
        description="Name of the Security Platform the rules are deployed on in OpenCTI.",
        default="Microsoft Sentinel",
        min_length=1,
    )
    platform_id: str | None = Field(
        description="Id (internal or STIX) of an existing Security Platform in "
        "OpenCTI the rules are deployed on, for example the one "
        "the Microsoft Sentinel stream connector of the same workspace reports to. "
        "Takes precedence over `platform_name` and `platform_type`: the connector "
        "references that platform and never rewrites it.",
        default=None,
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
    sentinel_analytics_rules: SentinelAnalyticsRulesConfig = Field(
        default_factory=SentinelAnalyticsRulesConfig
    )
