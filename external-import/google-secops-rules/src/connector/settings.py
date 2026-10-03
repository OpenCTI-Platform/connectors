"""Connector configuration.

`ExternalImportConnectorConfig` holds the options every EXTERNAL_IMPORT
connector has, with defaults for this connector; `GoogleSecOpsRulesConfig`
the options specific to Google SecOps. Values come from environment
variables (`GOOGLE_SECOPS_RULES_*`) or `config.yml`.
"""

from datetime import timedelta
from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="The unique identifier of the connector.",
        default="35a01a56-ebe1-412d-87a8-45c0a9d30fc9",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Google SecOps Detection Rules",
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


class GoogleSecOpsRulesConfig(BaseConfigModel):
    """Options specific to the Google SecOps detection rules connector."""

    project_id: str = Field(
        description="Google Cloud project bound to the Google SecOps instance "
        "(project id or number).",
        min_length=1,
    )
    project_region: str = Field(
        description="Region of the Google SecOps instance, e.g. `us`, `europe`, "
        "`europe-west2` or `asia-southeast1`.",
        min_length=1,
        pattern=r"^[a-z0-9-]+$",
    )
    project_instance: str = Field(
        description="Google SecOps instance (customer) id, a UUID shown in "
        "**SIEM Settings -> Profile**.",
        min_length=1,
    )
    client_email: str = Field(
        description="Email of the service account. It needs the `Chronicle API "
        "Viewer` role (`roles/chronicle.viewer`) on the project.",
        min_length=1,
    )
    private_key: SecretStr = Field(
        description="Private key of the service account (PEM, the `private_key` of "
        "its JSON key file). Literal `\\n` sequences are turned into line breaks.",
    )
    private_key_id: str | None = Field(
        description="Id of that private key (the `private_key_id` of the JSON key "
        "file).",
        default=None,
    )
    token_uri: HttpUrl = Field(
        description="OAuth 2.0 token endpoint of the service account.",
        default=HttpUrl("https://oauth2.googleapis.com/token"),
    )
    base_url: HttpUrl = Field(
        description="Chronicle API endpoint. The region is prefixed to its host at "
        "runtime (`https://<region>-chronicle.googleapis.com`).",
        default=HttpUrl("https://chronicle.googleapis.com"),
    )
    api_version: Literal["v1", "v1beta", "v1alpha"] = Field(
        description="Chronicle API version serving the rules and rule deployments.",
        default="v1alpha",
    )
    import_disabled_rules: bool = Field(
        description="Import rules that are not live too, with the deployment status "
        "`deployed` (live rules get `active`). When false, they are left out and "
        "count as removed.",
        default=True,
    )
    page_size: int = Field(
        description="Rules and rule deployments requested per page.",
        default=1000,
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
    platform_name: str = Field(
        description="Name of the Security Platform the rules are deployed on in OpenCTI.",
        default="Google SecOps",
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

    @field_validator("private_key", mode="before")
    @classmethod
    def _restore_pem_line_breaks(cls, value: Any) -> Any:
        """Environment variables often carry the PEM with literal ``\\n``."""
        if isinstance(value, str) and "\\n" in value:
            return value.replace("\\n", "\n")
        return value


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    google_secops_rules: GoogleSecOpsRulesConfig = Field(
        default_factory=GoogleSecOpsRulesConfig
    )
