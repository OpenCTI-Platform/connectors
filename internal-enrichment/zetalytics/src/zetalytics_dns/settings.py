"""Configuration models for the Zetalytics DNS connector."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


def _format_lookback_days(days: int) -> str:
    """Convert a lookback period in days into a short human-readable label.

    Whole-year and whole-month periods are shown as such (e.g. 730 -> "2 years",
    90 -> "3 months"). Periods of a year or longer that aren't an exact multiple
    of 365 days are shown as a fractional year rounded to 1 decimal place (e.g.
    912 -> "2.5 years"), so slightly "off" day counts (bad/imprecise input) still
    render as something meaningful instead of an unreadable raw day count.
    Everything shorter than a year that isn't a whole number of months falls
    back to a plain day count.
    """
    if days <= 0:
        return "0 days"
    if days % 365 == 0:
        years = days // 365
        return f"{years} year" if years == 1 else f"{years} years"
    if days >= 365:
        fractional_years = round(days / 365, 1)
        if fractional_years == int(fractional_years):
            whole_years = int(fractional_years)
            return f"{whole_years} year" if whole_years == 1 else f"{whole_years} years"
        return f"{fractional_years} years"
    if days % 30 == 0:
        months = days // 30
        return f"{months} month" if months == 1 else f"{months} months"
    return f"{days} day" if days == 1 else f"{days} days"


class _ConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        default="00000000-0000-4000-8000-000000000101",
        description="A UUID v4 identifying this connector instance in OpenCTI.",
    )
    name: str = Field(
        default="Zetalytics DNS - Analyst Enrichment",
        description=(
            "Display name for this connector in OpenCTI. The configured "
            "zetalytics.lookback_days is automatically appended, e.g. "
            "'Zetalytics DNS - Deep Investigation (2 years)'."
        ),
    )
    scope: ListFromString = Field(
        default=["Domain-Name", "Hostname", "IPv4-Addr", "IPv6-Addr"],
        description="Observable types this connector will enrich.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="info",
        description="Minimum log level to emit.",
    )


class _ZetalyticsConfig(BaseConfigModel):
    """All Zetalytics-specific settings.

    Env vars follow the pattern ZETALYTICS_<FIELD_NAME_UPPER>, e.g.
    ZETALYTICS_TOKEN, ZETALYTICS_MODE, ZETALYTICS_MAX_RESULTS.
    """

    token: SecretStr = Field(
        description="Zetalytics API token.",
    )
    request_timeout: int = Field(
        default=30,
        ge=5,
        description="HTTP request timeout in seconds for all Zetalytics API calls.",
    )
    mode: Literal["light", "playbook", "manual", "deep"] = Field(
        default="manual",
        description=(
            "Enrichment profile controlling which endpoints are called. "
            "Endpoint flags below override mode defaults."
        ),
    )
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
        description="Maximum TLP level of observables this connector will enrich.",
    )

    # --- Data volume controls ---
    max_results: int = Field(
        default=300,
        ge=1,
        description="Maximum passive DNS records to retrieve per query.",
    )
    max_subdomains: int = Field(
        default=300,
        ge=0,
        description="Maximum subdomains to retrieve.",
    )
    max_whois_results: int = Field(
        default=5,
        ge=0,
        description="Maximum historical WHOIS records to retrieve.",
    )
    max_ns_pivot_results: int = Field(
        default=100,
        ge=0,
        description="Maximum results for nameserver pivot queries.",
    )
    lookback_days: int = Field(
        default=365,
        ge=1,
        description="How many days back to query passive DNS records.",
    )
    tsfield: str = Field(
        default="all",
        description="Zetalytics timestamp field to filter on (all, last_seen, first_seen).",
    )

    # --- Endpoint feature flags ---
    include_live_dns: bool = Field(
        default=True,
        description="Perform a live DNS lookup in addition to passive DNS.",
    )
    include_subdomains: bool = Field(
        default=True,
        description="Retrieve known subdomains for domain enrichment.",
    )
    include_d8s: bool = Field(
        default=True,
        description="Retrieve structured D8S registration context for domains.",
    )
    include_historical_whois: bool = Field(
        default=False,
        description="Retrieve historical raw WHOIS data (disabled by default due to volume).",
    )
    include_ns_glue: bool = Field(
        default=True,
        description="Retrieve nameserver glue records.",
    )
    include_ns2domain: bool = Field(
        default=False,
        description="Pivot from nameserver to hosted domains (deep mode only).",
    )
    include_mx2domain: bool = Field(
        default=False,
        description="Pivot from MX domain to hosted domains (deep mode only).",
    )
    include_email_pivots: bool = Field(
        default=False,
        description="Enrich via registration email pivots (disabled by default).",
    )

    # --- STIX output controls ---
    confidence: int = Field(
        default=60,
        ge=0,
        le=100,
        description="Confidence score applied to created STIX objects.",
    )
    marking_definition: str = Field(
        default="TLP:AMBER",
        description="TLP marking definition to apply to created objects.",
    )
    create_note_when_no_results: bool = Field(
        default=False,
        description="Create an OpenCTI note on the observable when no results are found.",
    )
    include_portal_link: bool = Field(
        default=True,
        description=(
            "Add an external reference linking to the observable in the ZoneCruncher web "
            "portal. The link includes the API token as part of the URL path, which is "
            "visible to OpenCTI users who can view the observable. Set to false to omit."
        ),
    )


class ConfigLoader(BaseConnectorSettings):
    """Top-level settings container for the Zetalytics DNS connector."""

    connector: _ConnectorConfig = Field(  # type: ignore[assignment]
        default_factory=_ConnectorConfig,
        description="OpenCTI connector configuration.",
    )
    zetalytics: _ZetalyticsConfig = Field(
        description="Zetalytics API and enrichment configuration.",
    )

    @model_validator(mode="after")
    def _append_lookback_to_connector_name(self) -> "ConfigLoader":
        """Append the configured lookback period to the connector's display name.

        This keeps the name shown in OpenCTI's Enrichment tab (and connector list)
        in sync with `zetalytics.lookback_days` automatically, e.g.:
            "Zetalytics DNS - Deep Investigation" -> "Zetalytics DNS - Deep Investigation (2 years)"
        so analysts don't need to check the connector's config/environment to know
        how far back a given instance searches.

        Note: `connector` is a frozen `BaseConfigModel`, and `BaseConnectorSettings.__init__`
        doesn't honour a validator returning a new instance (see pydantic's
        "returning anything other than `self`" warning), so we mutate the nested
        frozen model in place via `object.__setattr__` rather than rebuilding it.
        """
        suffix = f" ({_format_lookback_days(self.zetalytics.lookback_days)})"
        if not self.connector.name.endswith(suffix):
            object.__setattr__(self.connector, "name", f"{self.connector.name}{suffix}")
        return self
