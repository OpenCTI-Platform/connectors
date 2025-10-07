from datetime import datetime, timedelta
from typing import Literal

from models.configs.base_settings import ConfigBaseSettings
from pydantic import Field, PositiveInt, SecretStr


def _get_default_start_date() -> str:
    """Get the default start date as 30 days ago from today."""
    date_30_days_ago = datetime.now() - timedelta(days=30)
    return date_30_days_ago.strftime("%Y-%m-%d")


class _ConfigLoaderMandiant(ConfigBaseSettings):
    """Interface for loading Mandiant dedicated configuration."""

    # Core Mandiant configuration
    api_v4_key_id: str = Field(
        description="Mandiant API v4 Key ID for authentication.",
    )
    api_v4_key_secret: SecretStr = Field(
        description="Mandiant API v4 Key Secret for authentication.",
    )

    # Marking definition
    marking_definition: Literal["amber+strict", "red", "green", "white"] = Field(
        default="amber+strict",
        alias="marking",
        description="TLP marking definition for imported data.",
    )

    # Import settings
    import_start_date: str = Field(
        default_factory=_get_default_start_date,
        description="Start date for data import (format: YYYY-MM-DD). Defaults to 30 days ago.",
    )
    indicator_import_start_date: str = Field(
        default_factory=_get_default_start_date,
        description="Start date for indicator import (format: YYYY-MM-DD). Defaults to 30 days ago.",
    )
    import_period: PositiveInt = Field(
        default=1,
        description="Import period in days.",
    )

    # Processing options
    create_notes: bool = Field(
        default=False,
        description="Whether to create notes from imported data.",
    )
    remove_statement_marking: bool = Field(
        default=False,
        description="Whether to remove statement markings from imported data.",
    )

    # Import toggles for different entity types
    import_actors: bool = Field(
        default=True,
        description="Whether to import threat actors.",
    )
    import_actors_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing actors.",
    )
    import_actors_aliases: bool = Field(
        default=False,
        description="Whether to import actor aliases.",
    )

    import_reports: bool = Field(
        default=True,
        description="Whether to import reports.",
    )
    import_reports_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing reports.",
    )

    import_malwares: bool = Field(
        default=True,
        description="Whether to import malware.",
    )
    import_malwares_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing malware.",
    )
    import_malwares_aliases: bool = Field(
        default=False,
        description="Whether to import malware aliases.",
    )

    import_campaigns: bool = Field(
        default=True,
        description="Whether to import campaigns.",
    )
    import_campaigns_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing campaigns.",
    )

    import_indicators: bool = Field(
        default=True,
        description="Whether to import indicators.",
    )
    import_indicators_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing indicators.",
    )
    import_indicators_with_full_campaigns: bool = Field(
        default=False,
        description="When importing indicators, import full campaigns (campaign details and related entities).",
    )

    import_vulnerabilities: bool = Field(
        default=False,
        description="Whether to import vulnerabilities.",
    )
    import_vulnerabilities_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours for importing vulnerabilities.",
    )

    # Report type configurations
    actor_profile_report: bool = Field(
        default=True,
        description="Whether to import actor profile reports.",
    )
    actor_profile_report_type: str = Field(
        default="actor-profile",
        description="Report type for actor profiles.",
    )

    country_profile_report: bool = Field(
        default=True,
        description="Whether to import country profile reports.",
    )
    country_profile_report_type: str = Field(
        default="country-profile",
        description="Report type for country profiles.",
    )

    event_coverage_implication_report: bool = Field(
        default=True,
        description="Whether to import event coverage/implication reports.",
    )
    event_coverage_implication_report_type: str = Field(
        default="event-coverage",
        description="Report type for event coverage/implication.",
    )

    executive_perspective_report: bool = Field(
        default=True,
        description="Whether to import executive perspective reports.",
    )
    executive_perspective_report_type: str = Field(
        default="executive-perspective",
        description="Report type for executive perspectives.",
    )

    ics_security_roundup_report: bool = Field(
        default=True,
        description="Whether to import ICS security roundup reports.",
    )
    ics_security_roundup_report_type: str = Field(
        default="ics-security-roundup",
        description="Report type for ICS security roundup.",
    )

    industry_reporting_report: bool = Field(
        default=True,
        description="Whether to import industry reporting reports.",
    )
    industry_reporting_report_type: str = Field(
        default="industry",
        description="Report type for industry reporting.",
    )

    malware_profile_report: bool = Field(
        default=True,
        description="Whether to import malware profile reports.",
    )
    malware_profile_report_type: str = Field(
        default="malware-profile",
        description="Report type for malware profiles.",
    )

    network_activity_report: bool = Field(
        default=True,
        description="Whether to import network activity reports.",
    )
    network_activity_report_type: str = Field(
        default="network-activity",
        description="Report type for network activity.",
    )

    patch_report: bool = Field(
        default=True,
        description="Whether to import patch reports.",
    )
    patch_report_type: str = Field(
        default="patch",
        description="Report type for patches.",
    )

    ttp_deep_dive_report: bool = Field(
        default=True,
        description="Whether to import TTP deep dive reports.",
    )
    ttp_deep_dive_report_type: str = Field(
        default="ttp-deep-dive",
        description="Report type for TTP deep dive.",
    )

    threat_activity_alert_report: bool = Field(
        default=True,
        description="Whether to import threat activity alert reports.",
    )
    threat_activity_alert_report_type: str = Field(
        default="threat-alert",
        description="Report type for threat activity alerts.",
    )

    threat_activity_report: bool = Field(
        default=True,
        description="Whether to import threat activity reports.",
    )
    threat_activity_report_type: str = Field(
        default="threat-activity",
        description="Report type for threat activity.",
    )

    trends_and_forecasting_report: bool = Field(
        default=True,
        description="Whether to import trends and forecasting reports.",
    )
    trends_and_forecasting_report_type: str = Field(
        default="trends-forecasting",
        description="Report type for trends and forecasting.",
    )

    vulnerability_report: bool = Field(
        default=True,
        description="Whether to import vulnerability reports.",
    )
    vulnerability_report_type: str = Field(
        default="vulnerability",
        description="Report type for vulnerabilities.",
    )

    vulnerability_import_software_cpe: bool = Field(
        default=True,
        description="Whether to import software CPE for vulnerabilities.",
    )

    vulnerability_max_cpe_relationship: PositiveInt = Field(
        default=200,
        description="Maximum number of CPE relationships for vulnerabilities.",
    )

    weekly_vulnerability_exploitation_report: bool = Field(
        default=True,
        description="Whether to import weekly vulnerability exploitation reports.",
    )
    weekly_vulnerability_exploitation_report_type: str = Field(
        default="vulnerability-exploitation",
        description="Report type for weekly vulnerability exploitation.",
    )

    news_analysis_report: bool = Field(
        default=True,
        description="Whether to import news analysis reports.",
    )
    news_analysis_report_type: str = Field(
        default="news-analysis",
        description="Report type for news analysis.",
    )

    # Relationship guessing configuration
    guess_relationships_reports: str = Field(
        default="Actor Profile, Malware Profile, Vulnerability Report",
        description="Comma-separated list of report types for which to guess relationships. Use 'All' for all types, 'None' to disable.",
    )
