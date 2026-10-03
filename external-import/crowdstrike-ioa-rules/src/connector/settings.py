"""Connector configuration.

`ExternalImportConnectorConfig` holds the options every EXTERNAL_IMPORT
connector has, with defaults for this connector; `CrowdStrikeIoaRulesConfig`
the options specific to CrowdStrike Falcon. Values come from environment
variables (`CROWDSTRIKE_IOA_RULES_*`) or `config.yml`.
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
        default="77bd979d-92b4-46f9-bf35-de4502411a9c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CrowdStrike Falcon Custom IOA Rules",
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


class CrowdStrikeIoaRulesConfig(BaseConfigModel):
    """Options specific to the CrowdStrike Falcon custom IOA rules connector."""

    base_url: HttpUrl = Field(
        description="CrowdStrike API base URL of your cloud: "
        "`https://api.crowdstrike.com` (US-1), `https://api.us-2.crowdstrike.com` "
        "(US-2), `https://api.eu-1.crowdstrike.com` (EU-1), "
        "`https://api.laggar.gcw.crowdstrike.com` (US-GOV-1).",
        default=HttpUrl("https://api.crowdstrike.com"),
    )
    client_id: str = Field(
        description="API client id. The API client needs the `Custom IOA rules: Read` "
        "scope, and `Prevention policies: Read` to check prevention policy "
        "assignments.",
        min_length=1,
    )
    client_secret: SecretStr = Field(
        description="API client secret.",
    )
    member_cid: str | None = Field(
        description="Child CID to read, for Flight Control (MSSP) parent API clients.",
        default=None,
    )
    rule_group_filter: str | None = Field(
        description="Optional FQL filter on rule groups, e.g. `platform:'windows'`.",
        default=None,
    )
    check_prevention_policies: bool = Field(
        description="Only count a rule as `active` when its rule group is assigned to "
        "an enabled prevention policy (a group runs on the hosts of its policies "
        "only). Needs the `Prevention policies: Read` scope; without it, a warning is "
        "logged and only the enabled state of rules and groups counts.",
        default=True,
    )
    import_disabled_rules: bool = Field(
        description="Import inactive rules too (disabled rules, rules of disabled "
        "groups or of groups assigned to no enabled prevention policy), with the "
        "deployment status `deployed` (active ones get `active`). When false, they "
        "are left out and count as removed.",
        default=True,
    )
    page_size: int = Field(
        description="Rule group ids requested per page.",
        default=100,
        ge=1,
        le=500,
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
        default="CrowdStrike Falcon",
        min_length=1,
    )
    platform_type: Literal["SIEM", "EDR", "XDR", "SOAR", "NDR", "ISPM"] = Field(
        description="Type of that Security Platform (`security_platform_type`).",
        default="EDR",
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates.",
        default=TLPLevel.AMBER,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    crowdstrike_ioa_rules: CrowdStrikeIoaRulesConfig = Field(
        default_factory=CrowdStrikeIoaRulesConfig
    )
