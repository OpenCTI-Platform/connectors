from datetime import datetime, timedelta, timezone
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from crowdstrike_feeds_services.utils import is_timestamp_in_future
from pydantic import (
    Field,
    HttpUrl,
    PositiveInt,
    SecretStr,
    SkipValidation,
    field_validator,
)


def _get_default_timestamp_30_days_ago() -> int:
    """Get Unix timestamp for 30 days ago."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    return int(thirty_days_ago.timestamp())


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        default="crowdstrike--1234abcd-1234-1234-1234-abcd12345678",
        description="A unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CrowdStrike",
    )
    scope: ListFromString = Field(
        default=["crowdstrike"],
        description=(
            "The scope or type of data the connector is importing, "
            "either a MIME type or Stix Object (for information only)."
        ),
    )
    duration_period: timedelta = Field(
        description="ISO8601 Duration format starting with 'P' for Period (e.g., 'PT30M' for 30 minutes).",
        default=timedelta(hours=1),
    )


class CrowdstrikeConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrowdstrikeConnector`.
    """

    # Core CrowdStrike configuration
    base_url: HttpUrl = Field(
        default=HttpUrl("https://api.crowdstrike.com"),
        description="CrowdStrike API base URL.",
    )
    client_id: SecretStr = Field(
        description="CrowdStrike API client ID for authentication.",
    )
    client_secret: SecretStr = Field(
        description="CrowdStrike API client secret for authentication.",
    )
    tlp: Literal["red", "amber+strict", "amber", "green", "clear", "white"] = Field(
        default="amber+strict",
        description="Default Traffic Light Protocol (TLP) marking for imported data.",
    )
    create_observables: bool = Field(
        default=True,
        description="Whether to create observables in OpenCTI.",
    )
    create_indicators: bool = Field(
        default=True,
        description="Whether to create indicators in OpenCTI.",
    )
    scopes: ListFromString = Field(
        default=[
            "actor",
            "report",
            "indicator",
            "malware",
            "yara_master",
            "snort_suricata_master",
        ],
        description=(
            "Comma-separated list of scopes to enable. "
            "Available: actor, report, indicator, malware, vulnerability, yara_master, snort_suricata_master."
        ),
    )

    # MITRE ATT&CK Enterprise lookup (technique name -> external_id like T1059)
    attack_version: str = Field(
        default="17.1",
        description=(
            "MITRE ATT&CK Enterprise version to use for technique ID resolution (e.g., 17.1). "
            "Should match the version imported by the MITRE ATT&CK external import connector."
        ),
    )
    attack_enterprise_url: HttpUrl | None = Field(
        default=None,
        description=(
            "Optional override URL for the MITRE ATT&CK Enterprise STIX dataset. "
            "If set, this URL is used instead of constructing one from attack_version. "
            "Useful for air-gapped environments or internal mirrors."
        ),
    )

    # Actor configuration
    actor_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing actors. Default is 30 days ago. BEWARE: 0 means ALL actors!",
    )

    # Malware configuration
    malware_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing malware. Default is 30 days ago. BEWARE: 0 means ALL malware!",
    )

    # Report configuration
    report_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing reports. Default is 30 days ago. BEWARE: 0 means ALL reports!",
    )
    report_status: Literal[
        "new",
        "in progress",
        "analyzed",
        "closed",
    ] = Field(
        default="new",
        description="Report status filter.",
    )
    report_include_types: ListFromString = Field(
        default=[
            "notice",
            "tipper",
            "intelligence report",
            "periodic report",
        ],
        description="Comma-separated list of report types to include.",
    )
    report_type: str = Field(
        default="threat-report",
        description="OpenCTI report type for imported reports.",
    )
    report_target_industries: ListFromString = Field(
        default=[],
        description="Comma-separated list of target industries to filter reports.",
    )
    report_guess_malware: bool = Field(
        default=False,
        description="Whether to use report tags to guess related malware.",
    )
    report_guess_relations: bool = Field(
        default=False,
        description="Whether to automatically guess and create relationships in reports.",
    )

    # Indicator configuration
    indicator_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing indicators. Default is 30 days ago. BEWARE: 0 means ALL indicators!",
    )
    indicator_exclude_types: ListFromString = Field(
        default=[
            "hash_ion",
            "hash_md5",
            "hash_sha1",
            "password",
            "username",
        ],
        description="Comma-separated list of indicator types to exclude from import.",
    )
    default_x_opencti_score: PositiveInt = Field(
        default=50,
        description="Default confidence score for entities without explicit score.",
    )
    indicator_low_score: PositiveInt = Field(
        default=40,
        description="Score assigned to indicators with low confidence labels.",
    )
    indicator_low_score_labels: ListFromString = Field(
        default=["MaliciousConfidence/Low"],
        description="Comma-separated list of labels indicating low confidence.",
    )
    indicator_medium_score: PositiveInt = Field(
        default=60,
        description="Score assigned to indicators with medium confidence labels.",
    )
    indicator_medium_score_labels: ListFromString = Field(
        default=["MaliciousConfidence/Medium"],
        description="Comma-separated list of labels indicating medium confidence.",
    )
    indicator_high_score: PositiveInt = Field(
        default=80,
        description="Score assigned to indicators with high confidence labels.",
    )
    indicator_high_score_labels: ListFromString = Field(
        default=["MaliciousConfidence/High"],
        description="Comma-separated list of labels indicating high confidence.",
    )
    indicator_unwanted_labels: ListFromString = Field(
        default=[],
        description=(
            "Comma-separated list of unwanted labels to filter out indicators. "
            "Can be used to filter low confidence indicators: 'MaliciousConfidence/Low,MaliciousConfidence/Medium'."
        ),
    )

    # Trigger import configuration
    no_file_trigger_import: bool = Field(
        default=True,
        description="Whether to trigger import without file dependencies.",
    )

    # Vulnerability configuration
    vulnerability_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing vulnerabilities. Default is 30 days ago. BEWARE: 0 means ALL vulnerabilities!",
    )

    # [DEPRECATED] Interval configuration
    interval_sec: SkipValidation[PositiveInt] = DeprecatedField(
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=x),
    )

    @field_validator("tlp", "report_status", mode="before")
    @classmethod
    def to_lowercase(cls, v: str) -> str:
        """Convert value to lowercase."""
        return v.lower()

    @field_validator(
        "actor_start_timestamp",
        "report_start_timestamp",
        "indicator_start_timestamp",
        mode="after",
    )
    @classmethod
    def check_start_timestamp(cls, value) -> int:
        if is_timestamp_in_future(value):
            raise ValueError(
                f"The provided timestamp value '{value}' is in the future."
            )
        return value

    @field_validator("attack_version", mode="after")
    @classmethod
    def format_attack_version(cls, value) -> str:
        if isinstance(value, str):
            # Accept versions like "v17.1" or "17.1".
            if value.lower().startswith("v"):
                value = value[1:]

        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CrowdstrikeConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    crowdstrike: CrowdstrikeConfig = Field(default_factory=CrowdstrikeConfig)
