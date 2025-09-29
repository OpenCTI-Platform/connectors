from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from connectors_sdk.core.pydantic import ListFromString
from models.configs.base_settings import ConfigBaseSettings
from pydantic import Field, HttpUrl, PositiveInt, SecretStr, field_validator


def _get_default_timestamp_30_days_ago() -> int:
    """Get Unix timestamp for 30 days ago."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    return int(thirty_days_ago.timestamp())


class _ConfigLoaderCrowdstrike(ConfigBaseSettings):
    """Interface for loading CrowdStrike dedicated configuration."""

    # Core CrowdStrike configuration
    base_url: HttpUrl = Field(
        default="https://api.crowdstrike.com",
        description="CrowdStrike API base URL.",
    )
    client_id: SecretStr = Field(
        description="CrowdStrike API client ID for authentication.",
    )
    client_secret: SecretStr = Field(
        description="CrowdStrike API client secret for authentication.",
    )
    tlp: Literal["red", "amber+strict", "amber", "green", "clear"] = Field(
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
            "yara_master",
            "snort_suricata_master",
        ],
        description=(
            "Comma-separated list of scopes to enable. "
            "Available: actor, report, indicator, yara_master, snort_suricata_master."
        ),
    )

    # Actor configuration
    actor_start_timestamp: int = Field(
        default=0,
        description="Unix timestamp from which to start importing actors. BEWARE: 0 means ALL actors!",
    )

    # Report configuration
    report_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing reports. Default is 30 days ago. BEWARE: 0 means ALL reports!",
    )
    report_status: Literal[
        "New",
        "In Progress",
        "Analyzed",
        "Closed",
    ] = Field(
        default="New",
        description="Report status filter.",
    )
    report_include_types: Optional[ListFromString] = Field(
        default=["notice", "tipper", "intelligence report", "periodic report"],
        description="Comma-separated list of report types to include.",
    )
    report_type: str = Field(
        default="threat-report",
        description="OpenCTI report type for imported reports.",
    )
    report_target_industries: Optional[ListFromString] = Field(
        default=None,
        description="Comma-separated list of target industries to filter reports.",
    )
    report_guess_malware: bool = Field(
        default=False,
        description="Whether to use report tags to guess related malware.",
    )

    # Indicator configuration
    indicator_start_timestamp: int = Field(
        default_factory=_get_default_timestamp_30_days_ago,
        description="Unix timestamp from which to start importing indicators. Default is 30 days ago. BEWARE: 0 means ALL indicators!",
    )
    indicator_exclude_types: Optional[ListFromString] = Field(
        default=["hash_ion", "hash_md5", "hash_sha1", "password", "username"],
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
    indicator_low_score_labels: Optional[ListFromString] = Field(
        default=["MaliciousConfidence/Low"],
        description="Comma-separated list of labels indicating low confidence.",
    )
    indicator_medium_score: PositiveInt = Field(
        default=60,
        description="Score assigned to indicators with medium confidence labels.",
    )
    indicator_medium_score_labels: Optional[ListFromString] = Field(
        default=["MaliciousConfidence/Medium"],
        description="Comma-separated list of labels indicating medium confidence.",
    )
    indicator_high_score: PositiveInt = Field(
        default=80,
        description="Score assigned to indicators with high confidence labels.",
    )
    indicator_high_score_labels: Optional[ListFromString] = Field(
        default=["MaliciousConfidence/High"],
        description="Comma-separated list of labels indicating high confidence.",
    )
    indicator_unwanted_labels: Optional[ListFromString] = Field(
        default=None,
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

    # Interval configuration
    interval_sec: PositiveInt = Field(
        default=1800,
        description="Polling interval in seconds for fetching data (used when duration_period is not set).",
    )

    @field_validator("report_status")
    def lowercase_report_status(cls, value):
        return value.lower()
