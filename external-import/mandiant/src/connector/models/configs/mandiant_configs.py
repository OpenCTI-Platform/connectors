from datetime import date, datetime, timedelta
from typing import Annotated, Literal

from connector.models.configs import ConfigBaseSettings
from pydantic import (
    AliasChoices,
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    PositiveInt,
    SecretStr,
)

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]
TLPToLower = Annotated[
    Literal[
        "white",
        "clear",
        "green",
        "amber",
        "amber+strict",
        "red",
    ],
    BeforeValidator(lambda v: v.lower() if isinstance(v, str) else v),
    PlainSerializer(lambda v: v.lower(), return_type=str),
]


def parse_date(value):
    date.fromisoformat(value)
    return value


DateToString = Annotated[
    str,
    BeforeValidator(parse_date),
]


def _get_default_start_date():
    """Get the default start date as 30 days ago from today."""
    return (datetime.now() - timedelta(days=30)).date().isoformat()


class ConfigLoaderMandiant(ConfigBaseSettings):
    """Interface for loading Mandiant dedicated configuration."""

    # ConfigLoader Mandiant
    api_v4_key_id: SecretStr = Field(
        description="Mandiant API v4 Key ID for authentication.",
    )
    api_v4_key_secret: SecretStr = Field(
        description="Mandiant API v4 Key Secret for authentication.",
    )

    marking: TLPToLower = Field(
        default="amber+strict",
        validation_alias=AliasChoices("marking_definition", "marking"),
        description="TLP Marking for data imported, possible values: white, clear, green, amber, amber+strict, red. "
        "NB: Some of the entities retrieved from the Mandiant portal already have a marking. We do not modify the "
        "marking on these entities. The marking defined by this parameter only takes into account entities created by "
        "the connector, or entities retrieved without marking.",
    )
    remove_statement_marking: bool = Field(
        default=False,
        description="Whether to remove statement markings from imported data.",
    )

    create_notes: bool = Field(
        default=False,
        description="Whether to create notes from imported data.",
    )

    import_start_date: DateToString = Field(
        default_factory=_get_default_start_date,
        description="Date to start collect data (Format: YYYY-MM-DD). "
        "Defaults to 30 days ago before first run the connector.",
    )
    import_period: PositiveInt = Field(
        default=1,
        description="Number of days to fetch in one round trip.",
    )

    indicator_import_start_date: DateToString = Field(
        default_factory=_get_default_start_date,
        description="Date to start collect indicators (Format: YYYY-MM-DD). "
        "Defaults to 30 days ago before first run the connector.",
    )
    indicator_minimum_score: PositiveInt = Field(
        default=80,
        description="Minimum score (based on mscore) that an indicator must have to be processed.",
    )

    import_indicators: bool = Field(
        default=True,
        description="Enable to collect indicators.",
    )
    import_indicators_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new indicators.",
    )

    import_actors: bool = Field(
        default=True,
        description="Enable to collect actors.",
    )
    import_actors_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new actors.",
    )
    import_actors_aliases: bool = Field(
        default=False,
        description="Import actors aliases.",
    )

    import_malwares: bool = Field(
        default=True,
        description="Enable to collect malwares.",
    )
    import_malwares_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new malwares.",
    )
    import_malwares_aliases: bool = Field(
        default=False,
        description="Import malwares aliases.",
    )

    import_campaigns: bool = Field(
        default=True,
        description="Enable to collect campaigns.",
    )
    import_campaigns_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new campaigns.",
    )
    import_indicators_with_full_campaigns: bool = Field(
        default=False,
        description="Enable to collect campaigns with related entities when importing IOC linked to this campaign.",
    )

    import_vulnerabilities: bool = Field(
        default=False,
        description="Enable to collect vulnerabilities.",
    )
    import_vulnerabilities_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new vulnerabilities.",
    )

    import_reports: bool = Field(
        default=True,
        description="Enable to collect reports.",
    )
    import_reports_interval: PositiveInt = Field(
        default=1,
        description="Interval in hours to check and collect new reports.",
    )

    actor_profile_report: bool = Field(
        default=True,
        description="Enable to collect report type 'actor_profile'.",
    )
    actor_profile_report_type: str = Field(
        default="actor-profile",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    country_profile_report: bool = Field(
        default=True,
        description="Enable to collect report type 'country_profile'.",
    )
    country_profile_report_type: str = Field(
        default="country-profile",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    event_coverage_implication_report: bool = Field(
        default=True,
        description="Enable to collect report type 'event_coverage_implication'.",
    )
    event_coverage_implication_report_type: str = Field(
        default="event-coverage",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    executive_perspective_report: bool = Field(
        default=True,
        description="Enable to collect report type 'executive_perspective'.",
    )
    executive_perspective_report_type: str = Field(
        default="executive-perspective",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    ics_security_roundup_report: bool = Field(
        default=True,
        description="Enable to collect report type 'ics_security_roundup'.",
    )
    ics_security_roundup_report_type: str = Field(
        default="ics-security-roundup",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    industry_reporting_report: bool = Field(
        default=True,
        description="Enable to collect report type 'industry_reporting'.",
    )
    industry_reporting_report_type: str = Field(
        default="industry",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    malware_profile_report: bool = Field(
        default=True,
        description="Enable to collect report type 'malware_profile'.",
    )
    malware_profile_report_type: str = Field(
        default="malware-profile",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    network_activity_report: bool = Field(
        default=True,
        description="Enable to collect report type 'network_activity_reports'.",
    )
    network_activity_report_type: str = Field(
        default="network-activity",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    patch_report: bool = Field(
        default=True,
        description="Enable to collect report type 'patch_report'.",
    )
    patch_report_type: str = Field(
        default="patch",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    ttp_deep_dive_report: bool = Field(
        default=True,
        description="Enable to collect report type 'ttp_deep_dive'.",
    )
    ttp_deep_dive_report_type: str = Field(
        default="ttp-deep-dive",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    threat_activity_alert_report: bool = Field(
        default=True,
        description="Enable to collect report type 'news_analysis'.",
    )
    threat_activity_alert_report_type: str = Field(
        default="threat-alert",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    threat_activity_report: bool = Field(
        default=True,
        description="Enable to collect report type 'threat_activity_report'.",
    )
    threat_activity_report_type: str = Field(
        default="threat-activity",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    trends_and_forecasting_report: bool = Field(
        default=True,
        description="Enable to collect report type 'trends_and_forecasting'.",
    )
    trends_and_forecasting_report_type: str = Field(
        default="trends-forecasting",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    vulnerability_report: bool = Field(
        default=True,
        description="Enable to collect report type 'vulnerability_report'.",
    )
    vulnerability_report_type: str = Field(
        default="vulnerability",
        description="Report type on vocabulary 'report_types_ov'.",
    )
    vulnerability_import_software_cpe: bool = Field(
        default=True,
        description="Enable to import CPE and version or not.",
    )
    vulnerability_max_cpe_relationship: PositiveInt = Field(
        default=200,
        description="Enable to define a maximum number of relationships created for a vulnerability.",
    )

    weekly_vulnerability_exploitation_report: bool = Field(
        default=True,
        description="Enable to collect report type 'weekly_vulnerability_exploitation_report'.",
    )
    weekly_vulnerability_exploitation_report_type: str = Field(
        default="vulnerability-exploitation",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    news_analysis_report: bool = Field(
        default=True,
        description="Enable to collect report type 'news_analysis'.",
    )
    news_analysis_report_type: str = Field(
        default="news-analysis",
        description="Report type on vocabulary 'report_types_ov'.",
    )

    guess_relationships_reports: str = Field(
        default="Actor Profile, Malware Profile, Vulnerability Report",
        description="Enable the capability to guess the relationships in selected reports type. "
        "Valid values: 'All, None, Actor Profile, Country Profile, Event Coverage/Implication, Executive Perspective, "
        "ICS Security Roundup, Industry Reporting, Malware Profile, Network Activity Reports, Patch Report, "
        "TTP Deep Dive, Threat Activity Alert, Threat Activity Report, Trends and Forecasting, Vulnerability Report, "
        "Weekly Vulnerability Exploitation Report, News Analysis'. "
        "Multiple values can be given in a string comma separated. If All or None is in the string it will override "
        "any other values. None is used before All.",
    )
