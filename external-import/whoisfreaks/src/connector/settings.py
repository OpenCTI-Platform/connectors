"""WhoisFreaks connector configuration."""

from datetime import timedelta
from typing import Annotated, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import BeforeValidator, Field, HttpUrl, SecretStr


def _parse_comma_separated_feed_types(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


_FeedTypes = Annotated[
    list[Literal["malware", "phishing", "spam"]],
    BeforeValidator(_parse_comma_separated_feed_types),
]
_NRDFeedTypes = Annotated[
    list[
        Literal[
            "nrd_gtld_with_whois",
            "nrd_cctld_with_whois",
            "nrd_gtld_without_whois",
            "nrd_cctld_without_whois",
        ]
    ],
    BeforeValidator(_parse_comma_separated_feed_types),
]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Configuration common to the WhoisFreaks external-import connector."""

    id: str = Field(
        description="Unique UUIDv4 identifier for this connector.",
        default="05ff90d6-548b-40ef-983b-79044f2d2dc6",
    )
    name: str = Field(
        description="Display name of the connector.",
        default="WhoisFreaks",
    )
    scope: ListFromString = Field(
        description="OpenCTI entity types imported by the connector.",
        default=[
            "indicator",
            "domain-name",
        ],
    )
    duration_period: timedelta = Field(
        description="Time between connector runs.",
        default=timedelta(hours=24),
    )


class WhoisFreaksConfig(BaseConfigModel):
    """Configuration specific to WhoisFreaks.

    Enable or disable individual feeds via ``feed_types`` and
    ``nrd_feed_types``. Only list feeds covered by your subscription;
    the connector will skip unavailable feeds and log a clear message
    when the API returns 401/403 (subscription / permission denied).
    """

    api_key: SecretStr = Field(
        description="WhoisFreaks API key.",
    )
    api_base_url: HttpUrl = Field(
        description="WhoisFreaks threat-feed stream API base URL.",
        default="https://files.whoisfreaks.com/v3.4/stream",
    )
    status_api_base_url: HttpUrl = Field(
        description="WhoisFreaks API status base URL.",
        default="https://files.whoisfreaks.com",
    )
    feed_types: _FeedTypes = Field(
        description=(
            "Threat feeds to import (subset of: malware, phishing, spam). "
            "Leave empty or omit feeds you are not subscribed to."
        ),
        default=[
            "malware",
            "phishing",
            "spam",
        ],
    )
    nrd_feed_types: _NRDFeedTypes = Field(
        description=(
            "NRD feeds to import. Valid values: "
            "nrd_gtld_with_whois, nrd_cctld_with_whois, "
            "nrd_gtld_without_whois, nrd_cctld_without_whois. "
            "Only enable feeds covered by your subscription."
        ),
        default=[
            "nrd_gtld_with_whois",
            "nrd_cctld_with_whois",
            "nrd_gtld_without_whois",
            "nrd_cctld_without_whois",
        ],
    )
    nrd_base_url: HttpUrl = Field(
        description="WhoisFreaks NRD stream API base URL.",
        default="https://files.whoisfreaks.com/v3.3/stream/domainer",
    )
    page_limit: int = Field(
        description=(
            "Number of CSV records requested per page. "
            "Higher values reduce HTTP overhead; keep within API limits "
            "and available memory (recommended 5000-10000 for large feeds)."
        ),
        default=5000,
        ge=1,
        le=100000,
    )
    nrd_timeout: int = Field(
        description="HTTP timeout in seconds for NRD feed requests.",
        default=180,
        ge=1,
    )
    threat_timeout: int = Field(
        description="HTTP timeout in seconds for threat-feed requests.",
        default=180,
        ge=1,
    )
    max_retries: int = Field(
        description="Max HTTP retries on transient errors (429/5xx).",
        default=5,
        ge=0,
        le=20,
    )
    retry_backoff_seconds: float = Field(
        description="Base seconds for exponential backoff between retries.",
        default=2.0,
        ge=0.1,
    )
    checkpoint_every_pages: int = Field(
        description=(
            "Update the in-memory offset every N pages; the connector persists "
            "state at the end of its callback."
        ),
        default=10,
        ge=1,
    )
    import_since: DatetimeFromIsoString = Field(
        description=(
            "Latest-snapshot floor date; snapshots older than this date are skipped. "
            "This does not trigger historical backfill. Accepts an ISO-8601 "
            "date-time or relative duration such as P7D."
        ),
        default="P1D",
        validate_default=True,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to imported STIX objects.",
        default=TLPLevel.CLEAR,
    )
    create_indicators_for_nrd: bool = Field(
        description=(
            "When true, create Indicator + based-on for NRD domains. "
            "When false, only Domain-Name observables are created "
            "(recommended for high-volume NRD feeds)."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Complete connector settings."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig,
    )
    whoisfreaks: WhoisFreaksConfig = Field(
        default_factory=WhoisFreaksConfig,
    )
