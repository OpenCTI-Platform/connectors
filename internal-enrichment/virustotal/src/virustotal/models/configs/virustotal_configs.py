import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from pydantic import (
    Field,
    PlainSerializer,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from virustotal.models.configs.base_settings import ConfigBaseSettings

# Relative date floor syntax for `ip_resolutions_since`: a number of days, e.g. `90d`.
_RELATIVE_SINCE_PATTERN = re.compile(r"^(\d+)d$", re.IGNORECASE)
# Keyword disabling the date floor for `ip_resolutions_since`.
NO_SINCE_FLOOR = "none"


def resolve_since_floor(value: str, now: datetime) -> datetime | None:
    """Resolve an `ip_resolutions_since` value to a UTC datetime.

    Parameters
    ----------
    value : str
        `none`, a relative number of days (`90d`) or an absolute date (`YYYY-MM-DD`).
    now : datetime
        Reference time for relative values (timezone-aware, UTC).

    Returns
    -------
    datetime | None
        The date floor, or ``None`` when the floor is disabled.

    Raises
    ------
    ValueError
        When the value matches none of the accepted formats.
    """
    if value.lower() == NO_SINCE_FLOOR:
        return None
    relative = _RELATIVE_SINCE_PATTERN.match(value)
    if relative:
        return now - timedelta(days=int(relative.group(1)))
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as err:
        raise ValueError(
            f"Invalid date floor '{value}': expected 'none', a number of days "
            "such as '90d', or a date such as '2025-10-01'."
        ) from err


TLPToLower = Annotated[
    Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class IndicatorConfig(ConfigBaseSettings):
    """Configuration for a given indicator type."""

    threshold: int
    valid_minutes: int
    detect: bool


class ConfigLoaderVirusTotal(ConfigBaseSettings):
    """Interface for loading VirusTotal dedicated configuration."""

    # Config Loader
    token: SecretStr = Field(
        description="VirusTotal API token for authentication.",
    )
    max_tlp: TLPToLower = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI. "
        "Available values: TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED",
    )
    replace_with_lower_score: bool = Field(
        default=True,
        description="Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true).",
    )

    # File/Artifact specific config settings
    file_create_note_full_report: bool = Field(
        default=True,
        description="Whether or not to include the full report as a Note.",
    )
    file_upload_unseen_artifacts: bool = Field(
        default=True,
        description="Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis.",
    )
    file_import_yara: bool = Field(
        default=True,
        description="Whether or not to import Crowdsourced YARA rules.",
    )
    file_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for File/Artifact based observables once this positive threshold is reached.",
    )
    file_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    file_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _file_indicator_config: IndicatorConfig = PrivateAttr()

    # IP specific config settings
    ip_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add ASN and location resolution relationships.",
    )
    ip_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for IPv4 based observables once this positive threshold is reached.",
    )
    ip_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    ip_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _ip_indicator_config: IndicatorConfig = PrivateAttr()
    ip_add_resolutions: bool = Field(
        default=False,
        description="Whether or not to import the domains resolving to the IP (VirusTotal resolutions) "
        "as Domain-Name observables linked with a dated `resolves-to` relationship. "
        "Off: no additional API call and no additional object.",
    )
    ip_resolutions_since: str = Field(
        default="90d",
        description="Date floor for IP resolutions: stop paging at the first resolution last seen before it. "
        "Absolute date (`YYYY-MM-DD`), relative number of days (`90d`, resolved at each enrichment) "
        "or `none` to disable the floor (the entry and page caps still apply).",
        examples=["90d", "2025-10-01", "none"],
    )
    ip_resolutions_max_entries: int | None = Field(
        default=None,
        ge=1,
        description="Entry cap for IP resolutions: stop after this many resolutions fetched per enrichment, "
        "newest first, counted before the keyword filter. Sent to VirusTotal as the page size when below 40. "
        "Unset: no entry cap.",
        examples=[3],
    )
    ip_resolutions_max_pages: int = Field(
        default=25,
        ge=1,
        description="Safety cap for IP resolutions: maximum number of pages (40 entries, one API lookup each) "
        "fetched per enrichment, whatever the date floor says.",
        examples=[25],
    )
    ip_resolutions_keywords: str | None = Field(
        default=None,
        description="Case-insensitive regular expression a resolved domain must match to be imported. "
        "Filters the created objects, not the API quota. Unset: import all resolved domains.",
        examples=["^news", "press"],
    )
    api_requests_per_minute: int = Field(
        default=4,
        ge=0,
        description="Spacing between IP resolutions pages, in requests per minute. "
        "4 fits a free API key; 0 disables the wait (premium keys). Applies only to IP resolutions paging.",
        examples=[4, 0],
    )

    # Domain specific config settings
    domain_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add IP resolution relationships.",
    )
    domain_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for Domain based observables once this positive threshold is reached.",
    )
    domain_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    domain_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _domain_indicator_config: IndicatorConfig = PrivateAttr()

    # URL specific config settings
    url_upload_unseen: bool = Field(
        default=True,
        description="Whether to upload URLs that VirusTotal has no record of for analysis.",
    )
    url_indicator_create_positives: int = Field(
        default=10,
        description="Create an indicator for URL based observables once this positive threshold is reached.",
    )
    url_indicator_valid_minutes: int = Field(
        default=2880,
        description="How long the indicator is valid for in minutes.",
    )
    url_indicator_detect: bool = Field(
        default=True,
        description="Whether or not to set detection for the indicator to true.",
    )
    _url_indicator_config: IndicatorConfig = PrivateAttr()

    # Generic config settings for File, IP, Domain, URL
    include_attributes_in_note: bool = Field(
        default=False,
        description="Whether or not to include the attributes info in Note.",
    )

    @field_validator("ip_resolutions_since")
    @classmethod
    def validate_ip_resolutions_since(cls, value: str) -> str:
        """Check the date floor format at start-up; it is resolved at each enrichment."""
        resolve_since_floor(value, datetime.now(timezone.utc))
        return value

    @field_validator("ip_resolutions_keywords")
    @classmethod
    def validate_ip_resolutions_keywords(cls, value: str | None) -> str | None:
        """Check that the keyword filter is a valid regular expression."""
        if value is not None:
            try:
                re.compile(value)
            except re.error as err:
                raise ValueError(
                    f"Invalid regular expression '{value}': {err}"
                ) from err
        return value

    @model_validator(mode="before")
    def auto_build_configs(cls, values: dict):
        """
        Automatically build configurations (File/IP/Domain/URL).
        """
        for prefix in ["file", "ip", "domain", "url"]:
            config_key = f"{prefix}_indicator_config"
            if not values.get(config_key):
                values[config_key] = IndicatorConfig(
                    threshold=values.get(f"{prefix}_indicator_create_positives", 10),
                    valid_minutes=values.get(f"{prefix}_indicator_valid_minutes", 2880),
                    detect=values.get(f"{prefix}_indicator_detect", True),
                )
        return values
