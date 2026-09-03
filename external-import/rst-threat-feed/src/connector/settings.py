from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from connectors_sdk.settings.deprecations import migrate_deprecated_namespace
from pydantic import Field, HttpUrl, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """OpenCTI external-import connector settings."""

    name: str = Field(
        description="The name of the connector.",
        default="RST Threat Feed",
        examples=["RST Threat Feed", "RST Threat Feed - Domain"],
    )
    duration_period: timedelta = Field(
        description=(
            "The period of time to await between two runs of the connector. "
            "Prefer ISO-8601 (e.g. PT24H). Legacy RST_THREAT_FEED_INTERVAL "
            "(seconds) is still accepted and mapped here."
        ),
        default=timedelta(hours=24),
        examples=["PT24H", "PT1H", "PT12H"],
    )
    queue_threshold: float = Field(
        description=(
            "Server capacity: max RabbitMQ queue size (in MB) before the "
            "connector pauses ingestion. Surfaced in the OpenCTI UI."
        ),
        default=500.0,
        gt=0,
        examples=[500.0],
    )
    update_existing_data: bool = Field(
        description="Whether to update existing STIX objects in OpenCTI.",
        default=True,
        examples=[True, False],
    )
    auto_create_service_account: bool = Field(
        description=(
            "Create a dedicated Connectors-group service account for this "
            "connector on first start and run subsequent API calls as that user."
        ),
        default=False,
        examples=[True, False],
    )
    auto_create_service_account_confidence_level: int = Field(
        description=(
            "Max confidence level for the auto-created connector service account."
        ),
        default=50,
        ge=0,
        le=100,
        examples=[50, 80],
    )


class RstThreatFeedConfig(BaseConfigModel):
    """RST Cloud Threat Feed API and import behaviour."""

    baseurl: HttpUrl = Field(
        description="RST Cloud API base URL.",
        default="https://api.rstcloud.net/v1",
        examples=["https://api.rstcloud.net/v1"],
    )
    apikey: str = Field(
        description="RST Cloud Threat Feed API key.",
        examples=["ChangeMe"],
    )
    contimeout: int = Field(
        description="HTTP connect timeout in seconds.",
        default=30,
        gt=0,
        examples=[30],
    )
    readtimeout: int = Field(
        description="HTTP read timeout in seconds for feed downloads.",
        default=120,
        gt=0,
        examples=[120, 600],
    )
    retry: int = Field(
        description="Per-request HTTP retry count for feed downloads.",
        default=2,
        ge=0,
        examples=[2],
    )
    ssl_verify: bool = Field(
        description="Verify TLS certificates for API requests.",
        default=True,
        examples=[True, False],
    )
    proxy: str = Field(
        description=(
            "Optional explicit forward proxy URL for feed downloads. "
            "When empty (default), requests honor standard HTTP_PROXY, "
            "HTTPS_PROXY, and NO_PROXY environment variables."
        ),
        default="",
        examples=["", "http://proxy.example.com:8080"],
    )
    latest: Literal["day", "1h", "4h", "12h"] = Field(
        description="Which feed snapshot window to download.",
        default="day",
        examples=["day", "1h", "4h", "12h"],
    )
    interval: int | None = Field(
        description=(
            "Deprecated. Run interval in seconds. Prefer "
            "CONNECTOR_DURATION_PERIOD. When set, overrides duration_period."
        ),
        default=None,
        gt=0,
        examples=[86400, 3600],
    )
    ip: bool = Field(
        description="Import the IP indicator feed.",
        default=True,
        examples=[True, False],
    )
    domain: bool = Field(
        description="Import the Domain indicator feed.",
        default=True,
        examples=[True, False],
    )
    url: bool = Field(
        description="Import the URL indicator feed.",
        default=True,
        examples=[True, False],
    )
    hash: bool = Field(
        description="Import the Hash (file) indicator feed.",
        default=True,
        examples=[True, False],
    )
    min_score_import: int = Field(
        description="Import only indicators with total score at or above this value.",
        default=20,
        ge=0,
        le=100,
        examples=[20, 40],
    )
    min_score_detection_ip: int = Field(
        description="Score threshold for x_opencti_detection on IPv4 indicators.",
        default=45,
        ge=0,
        le=100,
        examples=[45],
    )
    min_score_detection_domain: int = Field(
        description="Score threshold for x_opencti_detection on Domain indicators.",
        default=45,
        ge=0,
        le=100,
        examples=[45],
    )
    min_score_detection_url: int = Field(
        description="Score threshold for x_opencti_detection on URL indicators.",
        default=45,
        ge=0,
        le=100,
        examples=[45],
    )
    min_score_detection_hash: int = Field(
        description="Score threshold for x_opencti_detection on Hash indicators.",
        default=45,
        ge=0,
        le=100,
        examples=[45],
    )
    only_new: bool = Field(
        description="Skip indicators whose last-seen is older than the collect window.",
        default=True,
        examples=[True, False],
    )
    only_attributed: bool = Field(
        description="Import only indicators attributed to known threats.",
        default=False,
        examples=[False, True],
    )
    keep_named_vulns: bool = Field(
        description="Create named vulnerability objects (e.g. printnightmare).",
        default=True,
        examples=[True, False],
    )
    create_mitre_ttps: bool = Field(
        description=(
            "Create Attack-Pattern objects for MITRE TTP IDs and relate them "
            "to indicators. Can produce a large number of relationships."
        ),
        default=False,
        examples=[False, True],
    )
    create_custom_ttps: bool = Field(
        description=(
            "Create custom Attack-Pattern objects for named techniques not yet "
            "covered by MITRE ATT&CK."
        ),
        default=True,
        examples=[True, False],
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
    opencti_batch_size: int = Field(
        description=(
            "Max STIX objects per OpenCTI push. Large feeds (especially Domain) "
            "are flushed in chunks to bound memory and avoid oversized works."
        ),
        default=200,
        gt=0,
        examples=[100, 200, 500],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Connector configuration loaded from environment variables and config.yml."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rst_threat_feed: RstThreatFeedConfig = Field(default_factory=RstThreatFeedConfig)

    @classmethod
    def _migrate_deprecated_namespaces(cls, data: dict) -> dict:
        data = super()._migrate_deprecated_namespaces(data)
        migrate_deprecated_namespace(
            data,
            old_namespace="rst-threat-feed",
            new_namespace="rst_threat_feed",
        )
        feed = data.get("rst_threat_feed")
        if isinstance(feed, dict):
            if "create_mitre_ttp" in feed:
                feed.setdefault("create_mitre_ttps", feed.pop("create_mitre_ttp"))
            interval = feed.get("interval")
            if interval is not None:
                connector = data.setdefault("connector", {})
                if isinstance(connector, dict):
                    connector["duration_period"] = timedelta(seconds=int(interval))
        return data

    @model_validator(mode="after")
    def _require_api_key(self) -> "ConnectorSettings":
        feed_cfg = getattr(self, "rst_threat_feed", None)
        api_key = getattr(feed_cfg, "apikey", "")
        if not api_key:
            raise ValueError("rst_threat_feed.apikey is required.")
        return self
