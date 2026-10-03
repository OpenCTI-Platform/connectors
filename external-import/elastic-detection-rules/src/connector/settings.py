"""Connector configuration.

`ExternalImportConnectorConfig` holds the options every EXTERNAL_IMPORT
connector has, with defaults for this connector; `ElasticDetectionRulesConfig`
the options specific to Elastic Security. Values come from environment
variables (`ELASTIC_DETECTION_RULES_*`) or `config.yml`.
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
        default="ead3c71b-ab5d-49c4-a4c2-90ee9d47c585",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Elastic Security Detection Rules",
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


class ElasticDetectionRulesConfig(BaseConfigModel):
    """Options specific to the Elastic Security detection rules connector."""

    kibana_url: HttpUrl = Field(
        description="Base URL of Kibana, without the space prefix "
        "(e.g. `https://kibana.example.com:5601`).",
    )
    api_key: SecretStr = Field(
        description="Encoded Elasticsearch API key (the base64 `id:api_key` value), "
        "sent as `Authorization: ApiKey <key>`. It needs the Kibana privilege "
        "`Security > Rules and Exceptions: Read` in the space.",
    )
    space_id: str | None = Field(
        description="Kibana space holding the rules. Leave empty for the default space.",
        default=None,
    )
    rule_filter: str | None = Field(
        description="Optional KQL filter on rule attributes passed to the detection "
        'engine `_find` API (e.g. `alert.attributes.tags:"Production"`).',
        default=None,
    )
    import_disabled_rules: bool = Field(
        description="Import disabled rules too, with the deployment status `deployed` "
        "(enabled rules get `active`). When false, disabled rules are left out and "
        "count as removed.",
        default=True,
    )
    page_size: int = Field(
        description="Rules requested per page of the `_find` API.",
        default=100,
        ge=1,
        le=1000,
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
        description="Verify the TLS certificate of Kibana.",
        default=True,
    )
    platform_name: str = Field(
        description="Name of the Security Platform the rules are deployed on in OpenCTI.",
        default="Elastic Security",
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
    elastic_detection_rules: ElasticDetectionRulesConfig = Field(
        default_factory=ElasticDetectionRulesConfig
    )
