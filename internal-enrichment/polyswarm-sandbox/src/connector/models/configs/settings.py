"""Configuration for the PolySwarm Sandbox connector.

Uses connectors_sdk base classes (Criminal IP / upstream pattern).
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from polyswarm_api import settings as ps_settings
from pydantic import Field, SecretStr


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
    api_url: str = Field(
        default="https://api.polyswarm.network",
        description="PolySwarm API base URL.",
    )
    community: str = Field(
        default=ps_settings.DEFAULT_COMMUNITY,
        description="PolySwarm community (default or private).",
    )
    allow_public_community: bool = Field(
        default=False,
        description=(
            "Allow file uploads to the public PolySwarm community ('default'). "
            "Uploaded files become visible to the PolySwarm community, so this is off "
            "by default: set POLYSWARM_COMMUNITY to your private community, or set "
            "this to true to submit publicly."
        ),
    )
    timeout: int = Field(
        default=ps_settings.DEFAULT_HTTP_TIMEOUT,
        description="HTTP timeout for PolySwarm API calls in seconds.",
    )

    # TLP + score
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="Max TLP level of entities to enrich.",
    )
    replace_with_lower_score: bool = Field(
        default=True,
        description="If false, keep higher existing score instead of overwriting.",
    )

    # Sandbox settings
    sandbox_enabled: bool = Field(
        default=True,
        description="Enable sandbox analysis in addition to scan.",
    )
    sandbox_provider: str = Field(
        default="cape",
        description="Sandbox provider: cape, triage, or both.",
    )
    sandbox_vm_cape: str = Field(
        default="win-10-build-19041",
        description="VM slug for Cape sandbox submissions.",
    )
    sandbox_vm_triage: str = Field(
        default="windows11-21h2-x64",
        description="VM slug for Triage sandbox submissions.",
    )
    sandbox_vm: str | None = Field(
        default=None,
        description="Legacy single VM slug (overrides per-provider if set).",
    )
    sandbox_network_enabled: bool = Field(
        default=True,
        description="Enable internet access during sandbox analysis.",
    )
    sandbox_timeout: int = Field(
        default=600,
        description="Maximum wait time for sandbox results in seconds.",
    )
    sandbox_url_send_query: bool = Field(
        default=False,
        description=(
            "Send a Url observable's query string and fragment to PolySwarm for "
            "detonation. Off by default: only scheme, host and path are submitted, "
            "so tokens in a query string never leave OpenCTI."
        ),
    )
    sandbox_lookup_max_age_days: int = Field(
        default=0,
        ge=0,
        description=(
            "Hash lookup (StixFile observables) and report reuse (Artifacts): "
            "an existing PolySwarm sandbox report older than this many days is "
            "treated as missing. 0 means a report of any age is used."
        ),
    )
    sandbox_reuse_report: bool = Field(
        default=False,
        description=(
            "For an Artifact, look for an existing PolySwarm sandbox report by "
            "SHA-256 before uploading. When every configured provider has a usable "
            "report, it is used and the file is not uploaded again (the scan "
            "result is also taken from the latest existing scan of the hash)."
        ),
    )
    sandbox_detonate_by_hash: bool = Field(
        default=False,
        description=(
            "For a StixFile observable with no usable existing report, detonate "
            "the sample PolySwarm already holds for that hash. Nothing is uploaded "
            "from OpenCTI, but each detonation spends sandbox credits and runs in "
            "the community set in POLYSWARM_COMMUNITY. Off by default."
        ),
    )

    sandbox_max_dropped_files: int = Field(
        default=25,
        ge=0,
        description=(
            "Maximum dropped files per detonation to create as File observables "
            "related to the detonated observable (0 turns it off). Uses data "
            "already in the sandbox report."
        ),
    )
    sandbox_c2_indicators: bool = Field(
        default=True,
        description=(
            "Create Indicators (valid 30 days) for command and control addresses "
            "the sandbox report lists in an extracted malware configuration. "
            "Observables are created either way; needs create_indicators."
        ),
    )
    sandbox_attach_pcap: bool = Field(
        default=False,
        description=(
            "Download the sandbox network capture (pcap) and attach it to the "
            "observable. Off by default: it is an extra download per detonation."
        ),
    )
    sandbox_pcap_max_size: int = Field(
        default=26214400,
        ge=1,
        description=(
            "Largest pcap in bytes to attach (default 25MB). Larger captures "
            "are skipped."
        ),
    )

    # Polling
    poll_interval: int = Field(
        default=30,
        description="Seconds between poll attempts for scan/sandbox results.",
    )
    poll_timeout: int = Field(
        default=ps_settings.DEFAULT_SCAN_TIMEOUT,
        description="Maximum wait time for scan results in seconds.",
    )

    # Report toggles
    json_report_enabled: bool = Field(
        default=True,
        description="Attach raw JSON scan/sandbox data as a file.",
    )
    pdf_report_enabled: bool = Field(
        default=True,
        description="Request and attach PDF report from PolySwarm.",
    )
    llm_report_enabled: bool = Field(
        default=False,
        description="Request AI-generated analysis summary (opt-in).",
    )
    llm_report_timeout: int = Field(
        default=120,
        description="Maximum wait time for LLM report in seconds.",
    )

    # STIX creation
    min_polyscore: int = Field(
        default=50,
        description="Minimum PolyScore (0-100) to create indicators.",
    )
    create_indicators: bool = Field(
        default=True,
        description="Create STIX Indicator objects from scan results.",
    )
    create_observables: bool = Field(
        default=True,
        description="Create STIX Observable objects from sandbox IOCs.",
    )

    # File handling
    max_file_size: int = Field(
        default=33554432,
        description="Maximum file size in bytes (default 32MB).",
    )
    download_artifacts: bool = Field(
        default=True,
        description="Download file artifacts from OpenCTI for scanning.",
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

    # polykg (optional enrichment)
    polykg_api_url: str | None = Field(
        default=None,
        description="polykg REST API URL for malware profile enrichment (empty = disabled).",
    )


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector config with PolySwarm-specific defaults.

    Inherits ``type = INTERNAL_ENRICHMENT`` from the SDK base class.
    Only ``name`` and ``scope`` are overridden here; everything else
    (ID, confidence, log level) comes from env vars or SDK defaults.

    Scope is ``Artifact``, ``StixFile`` and ``Url``: the sandbox detonates an
    uploaded file (so it needs the file attached to an Artifact) or a URL. A
    StixFile observable carrying just a hash has no file to upload, so it gets
    the latest existing PolySwarm sandbox report for its hash (the lookup is read-only), and
    is only detonated when POLYSWARM_SANDBOX_DETONATE_BY_HASH is true.
    """

    name: str = Field(
        default="PolySwarm Sandbox",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["Artifact", "StixFile", "Url"],
        description="The scope of the connector.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level configuration — assembles OpenCTI, connector, and PolySwarm sections.

    Instantiate with no arguments; all values are read from the environment
    (or ``config.yml.sample`` when running locally). Call ``to_helper_config()``
    to produce the dict expected by ``OpenCTIConnectorHelper``.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig,
    )
    polyswarm: PolySwarmConfig = Field(
        default_factory=PolySwarmConfig,
    )
