"""Configuration for the PolySwarm Enrichment connector.

Uses connectors_sdk base classes for Pydantic-validated configuration.
All values are read from environment variables or config.yml.sample.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr, field_validator, model_validator


class PolySwarmConfig(BaseConfigModel):
    """PolySwarm-specific configuration.

    All fields map 1:1 to environment variables prefixed with ``POLYSWARM_``
    (e.g. ``POLYSWARM_API_KEY``).  Pydantic validates types at startup so
    misconfigurations surface immediately rather than at first enrichment.
    """

    # Required
    api_key: SecretStr = Field(
        description="PolySwarm API key for authentication.",
    )
    community: str = Field(
        default="default",
        description="PolySwarm community ('default' or 'private' for dual-community).",
    )

    # TLP + score
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        # An empty value used to mean "no limit", which TLP:RED now expresses.
        new_value_factory=lambda value: value or TLPLevel.RED,
        description="Max TLP level of entities to enrich (empty = no limit).",
    )
    replace_with_lower_score: bool = Field(
        default=True,
        description="If false, keep higher existing score instead of overwriting.",
    )

    # Polling
    max_polling_time: int = Field(
        default=120,
        description="Maximum wait time for scan results in seconds.",
    )

    # Network IOC extraction
    ioc_enabled: bool = Field(
        default=True,
        description="Enable network IOC extraction from PolySwarm IOC API.",
    )
    ioc_max_count: int = Field(
        default=20,
        description="Max network IOC observables per enrichment (global cap).",
    )
    ioc_score: int = Field(
        default=20,
        description="x_opencti_score for network IOC observables.",
    )
    ioc_types: ListFromString = Field(
        default=["ip", "domain", "url"],
        description="Which IOC types to create (comma-separated: ip,domain,url).",
    )

    # Rescan stale hashes (off by default: each rescan spends scan quota)
    rescan_older_than_days: int = Field(
        default=0,
        ge=0,
        le=36500,
        description=(
            "Ask PolySwarm to rescan a sample it already holds when its latest scan "
            "is older than this many days, or when it has no completed scan "
            "(0 = never rescan, maximum 36500). Each rescan spends PolySwarm scan quota. Nothing is "
            "uploaded: PolySwarm rescans its own copy of the sample."
        ),
    )
    rescan_timeout: int = Field(
        default=300,
        ge=1,
        description=(
            "Maximum seconds to wait for a rescan to finish. On timeout the "
            "enrichment uses the previous scan result and says so in the note."
        ),
    )

    # Sample download (off by default: stores live malware in OpenCTI)
    download_sample: bool = Field(
        default=False,
        description=(
            "Download the sample for a File PolySwarm holds and store it as an "
            "Artifact in OpenCTI. This puts LIVE MALWARE in OpenCTI file storage "
            "and spends PolySwarm download quota. Off by default."
        ),
    )
    download_max_size_mb: int = Field(
        default=20,
        ge=1,
        description=(
            "Largest sample, in MB, that will be downloaded. Larger samples are "
            "skipped and the note says so."
        ),
    )

    # URL, domain and IP observable lookups
    network_related_files_max: int = Field(
        default=10,
        ge=0,
        description=(
            "Max related file hashes to import when enriching an IP or domain "
            "observable (0 = disabled)."
        ),
    )
    network_url_send_query: bool = Field(
        default=False,
        description=(
            "Send a URL observable's query string and fragment to PolySwarm. Off by "
            "default: only scheme, host and path are looked up, so tokens in a query "
            "string never leave OpenCTI."
        ),
    )
    network_indicator_min_detections: int = Field(
        default=2,
        ge=1,
        description=(
            "Minimum malicious engine detections on a URL, domain or IP scan "
            "before an Indicator is created."
        ),
    )

    # Account quota visibility (read-only)
    quota_warn_below: int = Field(
        default=100,
        ge=0,
        description=(
            "Log a warning when the remaining daily API quota, or a sandbox or "
            "hunt allowance, falls below this number (0 = no warnings). Accounts "
            "with no cap are never warned."
        ),
    )

    # Pivots (off by default: every pivot costs PolySwarm API lookups)
    pivot_imphash_max: int = Field(
        default=0,
        ge=0,
        le=100,
        description=(
            "Max other files with the same imphash to import when enriching a "
            "file PolySwarm reports a PE imphash for (0 = off, e.g. 10). Imported "
            "files are labelled polyswarm-pivot-result and never pivot again."
        ),
    )
    pivot_ttp_max: int = Field(
        default=0,
        ge=0,
        le=100,
        description=(
            "Max files to import when enriching an Attack-Pattern with a MITRE "
            "ATT&CK id (0 = off, e.g. 10). Any value above 0 adds Attack-Pattern "
            "to the default connector scope; if you set CONNECTOR_SCOPE "
            "yourself, add Attack-Pattern to it or OpenCTI will not offer this "
            "connector for Attack-Patterns. Runs only with CONNECTOR_AUTO=false: with auto "
            "enrichment on, every Attack-Pattern created would trigger a search."
        ),
    )
    # YARA hunting from OpenCTI Indicators. Off by default: it creates hunts in
    # the PolySwarm account of the API key and spends hunt quota.
    yara_hunt_enabled: bool = Field(
        default=False,
        description=(
            "Run a PolySwarm historical hunt for each YARA Indicator that is "
            "enriched. Writes to your PolySwarm account (creates hunts), spends "
            "hunt quota, and sends the YARA rule text to PolySwarm. Adds "
            "Indicator to the default connector scope; if you set "
            "CONNECTOR_SCOPE yourself, add Indicator to it or OpenCTI will not "
            "offer this connector for Indicators."
        ),
    )
    yara_hunt_window_days: int = Field(
        default=30,
        description="How many days back a hunt reaches: 30, 60, 90 or 180.",
    )
    yara_hunt_timeout: int = Field(
        default=300,
        ge=60,
        description=(
            "Seconds to wait for a hunt before reporting it as still running "
            "(hunts can be slow)."
        ),
    )
    yara_hunt_max_results: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Max matched files imported as File observables per hunt.",
    )

    @field_validator("yara_hunt_window_days")
    @classmethod
    def _check_window_days(cls, value: int) -> int:
        if value not in (30, 60, 90, 180):
            raise ValueError("must be one of 30, 60, 90 or 180")
        return value

    # polykg (optional enrichment).
    # Default is empty (disabled) so an out-of-the-box deployment never
    # silently points at a staging environment. Operators who want
    # malware-profile enrichment must supply their production polykg URL
    # explicitly via ``POLYKG_API_URL`` / the ``polykg.api_url`` YAML key.
    polykg_api_url: str = Field(
        default="",
        description="polykg REST API URL for malware profile enrichment (empty = disabled).",
    )


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector config with PolySwarm-specific defaults."""

    name: str = Field(
        default="PolySwarm Hash Enrichment",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "StixFile",
            "Artifact",
            "Url",
            "Domain-Name",
            "IPv4-Addr",
            "IPv6-Addr",
        ],
        description="The scope of the connector.",
    )
    max_tlp: TLPLevel = Field(
        description=(
            "The highest TLP of the entities the connector is allowed to enrich. "
            "Entities marked with a higher TLP are skipped and never sent to the external source."
        ),
        default=TLPLevel.RED,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level configuration — assembles OpenCTI, connector, and PolySwarm sections.

    Instantiate with no arguments; all values are read from the environment.
    Call ``to_helper_config()`` to produce the dict expected by
    ``OpenCTIConnectorHelper``.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig,
    )
    polyswarm: PolySwarmConfig = Field(
        default_factory=PolySwarmConfig,
    )

    @model_validator(mode="after")
    def _scope_follows_features(self) -> "ConnectorSettings":
        """Add the entity types the enabled features need to the scope.

        Attack-Pattern when the technique pivot is on, Indicator when YARA
        hunting is on. Each type is added once; the scope is rebuilt as a new
        list and set once.
        """
        scope = list(self.connector.scope)
        present = {item.strip().lower() for item in scope}
        needed = []
        if self.polyswarm.pivot_ttp_max > 0:
            needed.append("Attack-Pattern")
        if self.polyswarm.yara_hunt_enabled:
            needed.append("Indicator")
        added = [name for name in needed if name.lower() not in present]
        if added:
            # The models are frozen; this is the one derived value
            object.__setattr__(self.connector, "scope", scope + added)
        return self
