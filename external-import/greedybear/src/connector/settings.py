from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="GreedyBear",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Autonomous-System",
            "Location",
            "Infrastructure",
        ],
    )
    duration_period: timedelta = Field(
        description="Interval between two runs of the connector.",
        default=timedelta(hours=6),
    )


class GreedyBearConfig(BaseConfigModel):
    # Connection
    api_base_url: HttpUrl = Field(
        description="GreedyBear base URL, e.g. https://greedybear.example.com"
    )
    api_key: Optional[SecretStr] = Field(
        description=(
            "GreedyBear API token (used for advanced and ASN feeds). "
            "Leave empty to use only the public standard feed (no auth required)."
        ),
        default=None,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="Default TLP level for all imported entities.",
            default="green",
        )
    )

    # Operator / Author identity (the honeypot operator - NOT GreedyBear itself)
    operator_name: str = Field(
        description=(
            "Name of the organization operating the honeypots. "
            "This becomes the 'created by' identity in OpenCTI."
        ),
        default="Honeypot Operator",
    )
    operator_description: Optional[str] = Field(
        description="Optional description of the honeypot operator.",
        default=None,
    )
    operator_url: Optional[str] = Field(
        description="Optional URL of the honeypot operator (website, GitHub, etc.).",
        default=None,
    )

    # Feed selection
    feed_type: str = Field(
        description=(
            "Honeypot feed type. Comma-separated names or 'all'. "
            "Valid values: all, cowrie, dionaea, adbhoney, ciscoasa, conpot, ..."
        ),
        default="all",
    )
    attack_type: str = Field(
        description="Attack type filter: 'scanner', 'payload_request', or 'all'.",
        default="all",
    )
    ioc_type: str = Field(
        description="IoC type filter: 'ip', 'domain', or 'all'.",
        default="all",
    )

    # Prioritization - only used when advanced feed is unavailable (standard feed fallback)
    prioritize: str = Field(
        description=(
            "Standard feed prioritization: "
            "'recent', 'persistent', 'likely_to_recur', 'most_expected_hits'."
        ),
        default="recent",
    )

    # Reputation filters
    include_mass_scanners: bool = Field(
        description="Include IoCs flagged as mass scanners.",
        default=False,
    )
    include_tor_exit_nodes: bool = Field(
        description="Include IoCs flagged as Tor exit nodes.",
        default=True,
    )

    # Advanced feed parameters
    max_age: int = Field(
        description="Maximum age of entries in days (advanced feed, default 3).",
        default=3,
    )
    feed_size: int = Field(
        description="Maximum number of IoCs to import per run (default 5000).",
        default=5000,
    )
    min_score: Optional[float] = Field(
        description="Minimum recurrence_probability (0.0-1.0). None means no filter.",
        default=None,
    )
    create_indicators: bool = Field(
        description=(
            "Create STIX Indicators for every imported observable. "
            "Indicators are linked via based-on to the observable and via indicates "
            "to the MITRE Attack Pattern (if known)."
        ),
        default=True,
    )
    deep_enrich: bool = Field(
        description=(
            "Per-IoC enrichment call adding the actual destination ports and the "
            "days-seen count to the Note, plus FireHOL blocklist categories as "
            "labels. One extra API call per IoC - slow for large feeds; needs an API key."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Root settings model.
    Section name 'greedybear' maps to env prefix GREEDYBEAR_
    (e.g. GREEDYBEAR_API_BASE_URL, GREEDYBEAR_OPERATOR_NAME, ...).
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    greedybear: GreedyBearConfig = Field(default_factory=GreedyBearConfig)
