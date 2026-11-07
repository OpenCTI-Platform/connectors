from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.settings.annotated_types import ListFromString
from connectors_sdk.settings.deprecations import migrate_deprecated_namespace
from pydantic import Field, HttpUrl, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """OpenCTI external-import connector settings."""

    name: str = Field(
        description="The name of the connector.",
        default="RST Threat Library",
        examples=["RST Threat Library"],
    )
    scope: ListFromString = Field(
        description=(
            "The scope of the connector: STIX domain types emitted "
            "(intrusion-set, malware, tool, campaign)."
        ),
        default=["intrusion-set", "malware", "tool", "campaign"],
        examples=[["intrusion-set", "malware", "tool", "campaign"]],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
        examples=["PT1H", "PT30M"],
    )
    tlp_level: TLPLevel = Field(
        description=(
            "TLP marking applied to imported objects. The marking definition "
            "is included in each bundle sent to OpenCTI."
        ),
        default=TLPLevel.CLEAR,
        examples=["clear", "amber"],
    )


class RstThreatLibraryConfig(BaseConfigModel):
    """RST Cloud Threat Library API and sync behaviour."""

    baseurl: HttpUrl = Field(
        description="RST Cloud API base URL.",
        default="https://api.rstcloud.net/v1",
        examples=["https://api.rstcloud.net/v1"],
    )
    apikey: SecretStr = Field(
        description="RST Cloud Threat Library API key.",
        examples=["ChangeMe"],
        json_schema_extra={
            "format": "password",
            "writeOnly": True,
        },
    )
    auth_header: str = Field(
        description="HTTP header name used to send the API key.",
        default="x-api-key",
        examples=["x-api-key"],
    )
    contimeout: int = Field(
        description="HTTP connect timeout in seconds.",
        default=30,
        gt=0,
        examples=[30],
    )
    readtimeout: int = Field(
        description="HTTP read timeout in seconds.",
        default=120,
        gt=0,
        examples=[120, 600],
    )
    retry: int = Field(
        description="Per-request HTTP retry count.",
        default=2,
        ge=0,
        examples=[2, 10],
    )
    ssl_verify: bool = Field(
        description="Verify TLS certificates for API requests.",
        default=True,
        examples=[True, False],
    )
    page_size: int = Field(
        description="Page size (limit) for Threat Library list requests.",
        default=100,
        gt=0,
        examples=[20, 100],
    )
    order_by: str = Field(
        description="Sort field for incremental polling.",
        default="modified",
        examples=["modified"],
    )
    order_mode: Literal["asc", "desc"] = Field(
        description="Sort direction for incremental polling.",
        default="desc",
        examples=["desc", "asc"],
    )
    proxy: str = Field(
        description="Optional forward HTTP proxy URL. Empty means direct egress.",
        default="",
        examples=["", "http://proxy.example.com:8080"],
    )
    max_retries: int = Field(
        description="Maximum attempts when pushing bundles to OpenCTI.",
        default=3,
        ge=1,
        examples=[3],
    )
    retry_delay: int = Field(
        description=(
            "Initial retry delay in seconds for OpenCTI push failures. "
            "The connector sleeps at least 1 second between retries."
        ),
        default=10,
        ge=0,
        examples=[10],
    )
    retry_backoff_multiplier: float = Field(
        description="Exponential backoff multiplier for OpenCTI push retries.",
        default=2.0,
        gt=0,
        examples=[2.0],
    )
    object_types: ListFromString = Field(
        description="Comma-separated threat-object paths to poll.",
        default="intrusion-sets,malware,tools,campaigns",
        examples=["intrusion-sets,malware,tools,campaigns"],
    )
    import_from_date: str = Field(
        description="Optional initial backfill cutoff (YYYY-MM-DD).",
        default="",
        examples=["", "2024-01-01"],
    )
    opencti_batch_size: int = Field(
        description=(
            "Max STIX objects per OpenCTI push. Large deltas are flushed in "
            "chunks to bound memory and avoid oversized bundles."
        ),
        default=200,
        gt=0,
        examples=[100, 200, 500],
    )
    sync_labels: ListFromString = Field(
        description="Labels merged on import; scopes merge/split.",
        default="RST Threat Library",
        examples=["RST Threat Library"],
    )
    reconcile_exclude_labels: ListFromString = Field(
        description="Entities with these labels are excluded from merge/split fusion.",
        default="",
        examples=["", "MITRE,manual"],
    )
    reconcile_allow_created_by: ListFromString = Field(
        description="If set, merge/split fuses only entities with these createdBy IDs.",
        default="",
        examples=["", "identity--11111111-1111-1111-1111-111111111111"],
    )
    merge_split: bool = Field(
        description=(
            "Enable alias merge/split reconcile for intrusion sets, malware, "
            "tools, and campaigns via the OpenCTI API "
            "(stix.merge / alias field updates)."
        ),
        default=False,
        examples=[False, True],
    )
    respect_user_edits: bool = Field(
        description="Preserve OpenCTI content when its confidence exceeds upstream.",
        default=False,
        examples=[False, True],
    )
    intrusion_set_default_confidence: int | None = Field(
        description=(
            "When set, replaces Threat Library confidence on imported "
            "intrusion sets (STIX confidence / OpenCTI source confidence)."
        ),
        default=None,
        ge=0,
        le=100,
        examples=[None, 80],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Connector configuration loaded from environment variables and config.yml."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rst_threat_library: RstThreatLibraryConfig = Field(
        default_factory=RstThreatLibraryConfig
    )

    @classmethod
    def _migrate_deprecated_namespaces(cls, data: dict) -> dict:
        data = super()._migrate_deprecated_namespaces(data)
        migrate_deprecated_namespace(
            data,
            old_namespace="rst-threat-library",
            new_namespace="rst_threat_library",
        )
        return data

    @model_validator(mode="after")
    def _require_api_key(self) -> "ConnectorSettings":
        threat_library_cfg = getattr(self, "rst_threat_library", None)
        api_key = getattr(threat_library_cfg, "apikey", None)
        if api_key is None or not api_key.get_secret_value():
            raise ValueError("rst_threat_library.apikey is required.")
        return self
