import os
from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import (
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
    model_validator,
)


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Define defaults for the OpenCTI external-import connector runtime."""

    name: str = Field(default="RansomLook", description="Connector display name.")
    scope: ListFromString = Field(
        default=[
            "artifact",
            "attack-pattern",
            "cryptocurrency-wallet",
            "ipv4-addr",
            "ipv6-addr",
            "identity",
            "indicator",
            "infrastructure",
            "intrusion-set",
            "threat-actor",
            "incident",
            "malware",
            "report",
            "note",
            "domain-name",
            "url",
            "relationship",
        ],
        description="STIX entity types imported by the connector.",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=1),
        description="Period between connector runs.",
    )


class RansomLookConfig(BaseConfigModel):
    """Define source-specific RansomLook collection behavior."""

    model_config = ConfigDict(
        hide_input_in_errors=True,
        extra="ignore",
        frozen=True,
        validate_default=True,
    )

    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://www.ransomlook.io/api"),
        description="RansomLook API base URL.",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="Optional API key sent in the Authorization header.",
    )
    labels: ListFromString = Field(
        default=["ransomware", "ransomlook"],
        description="Labels applied to imported entities.",
    )
    marking_definition: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(default="TLP:CLEAR", description="TLP marking for imported data.")
    initial_history_days: int = Field(
        default=7,
        ge=1,
        le=3650,
        description="Lookback used on the first connector run.",
    )
    max_response_size_mb: int = Field(
        default=32,
        ge=1,
        le=256,
        description="Maximum accepted size of one RansomLook API response in MiB.",
    )
    max_records_per_endpoint: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description=(
            "Maximum top-level records accepted from one endpoint or collection, "
            "and nested torrent context values retained per group."
        ),
    )
    max_pages_per_endpoint: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum pages requested from a paginated endpoint per run.",
    )
    max_requests_per_run: int = Field(
        default=2000,
        ge=10,
        le=100000,
        description="Maximum physical RansomLook HTTP attempts in one run.",
    )
    max_run_duration_seconds: int = Field(
        default=2700,
        ge=60,
        le=86400,
        description="Wall-clock deadline shared by all RansomLook requests in a run.",
    )
    work_reconciliation_timeout_seconds: int = Field(
        default=900,
        ge=10,
        le=7200,
        description=(
            "Maximum time to wait for OpenCTI workers to complete one logical "
            "delivery before retaining its cursor for replay."
        ),
    )
    max_objects_per_bundle: int = Field(
        default=500,
        ge=32,
        le=5000,
        description="Maximum STIX objects in one dependency-complete input bundle.",
    )
    max_objects_per_run: int = Field(
        default=20000,
        ge=100,
        le=200000,
        description=(
            "Maximum STIX objects accumulated during one connector run before "
            "undelivered claims are retained for retry."
        ),
    )
    max_bundle_size_mb: int = Field(
        default=64,
        ge=1,
        le=256,
        description=(
            "Maximum serialized size of one dependency-complete input bundle in "
            "MiB before queue transport; must cover configured post evidence."
        ),
    )
    replay_window_days: int = Field(
        default=1,
        ge=0,
        le=6,
        description="Days replayed before the claims cursor to collect late posts.",
    )
    max_artifact_size_mb: int = Field(
        default=5,
        ge=1,
        le=32,
        description="Maximum decoded size of one screenshot or source Artifact in MiB.",
    )
    max_artifacts_per_claim: int = Field(
        default=2,
        ge=1,
        le=20,
        description="Maximum evidence Artifacts decoded for one victim claim.",
    )
    max_artifacts_per_location: int = Field(
        default=2,
        ge=1,
        le=20,
        description="Maximum evidence Artifacts decoded for one actor location.",
    )
    max_artifacts_per_run: int = Field(
        default=300,
        ge=1,
        le=10000,
        description="Maximum evidence Artifacts decoded during one connector run.",
    )
    max_artifact_bytes_per_run_mb: int = Field(
        default=200,
        ge=1,
        le=4096,
        description="Maximum total decoded evidence bytes per run, in MiB.",
    )
    max_evidence_serialized_bytes_per_run_mb: int = Field(
        default=800,
        ge=1,
        le=16384,
        description=(
            "Maximum aggregate base64 evidence bytes retained across Artifacts "
            "and Report files during one run, in MiB."
        ),
    )
    max_pending_claims: int = Field(
        default=5000,
        ge=1,
        le=100000,
        description="Maximum incomplete claim records retained for bounded retry.",
    )
    max_claim_retries: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum retry attempts for incomplete claim detail or evidence.",
    )
    max_pending_groups: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum actor-profile groups retained for bounded retry.",
    )
    max_enrichment_retries: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum retry attempts for transient actor-profile enrichment.",
    )
    retry_max_age_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Maximum age of claim and enrichment retry work.",
    )
    enrich_actor_profiles: bool = Field(
        default=True,
        description="Enrich profiles for groups encountered in the claims window.",
    )
    import_infrastructure: bool = Field(
        default=True,
        description="Import typed actor infrastructure for encountered groups.",
    )
    import_sensitive_infrastructure: bool = Field(
        default=False,
        description="Import private, chat, admin, and file-server location values.",
    )
    import_post_evidence: bool = Field(
        default=True,
        description="Import bounded screenshot and HTML evidence attached to claims.",
    )
    import_location_evidence: bool = Field(
        default=False,
        description="Import bounded captures attached to actor infrastructure.",
    )
    import_notes: bool = Field(
        default=True,
        description="Import ransom notes associated with encountered groups.",
    )
    import_wallets: bool = Field(
        default=True,
        description="Import cryptocurrency wallets associated with encountered groups.",
    )
    import_torrents: bool = Field(
        default=True,
        description="Import bounded torrent and magnet intelligence.",
    )
    import_torrent_peers: bool = Field(
        default=False,
        description="Import torrent peer telemetry as context; never as Indicators.",
    )
    import_leaks: bool = Field(
        default=True,
        description="Import deterministically related leak evidence.",
    )
    import_analyses: bool = Field(
        default=True,
        description="Import explicit technical analyses, malware, and TTP mappings.",
    )
    import_victim_websites: bool = Field(
        default=True,
        description="Import victim website observables as non-malicious context.",
    )
    create_indicators: bool = Field(
        default=False,
        description="Create Indicators only for explicit upstream malicious assertions.",
    )

    @field_validator("labels")
    @classmethod
    def normalize_labels(cls, value: ListFromString) -> list[str]:
        """Normalize labels and reject an empty effective label set."""
        labels = list(dict.fromkeys(label.strip() for label in value if label.strip()))
        if not labels:
            raise ValueError("At least one non-empty RansomLook label is required")
        return labels

    @model_validator(mode="after")
    def validate_configuration(self) -> "RansomLookConfig":
        """Validate endpoint safety and compatible transport/evidence bounds."""
        if self.api_base_url.username or self.api_base_url.password:
            raise ValueError("RansomLook API base URL must not contain credentials")
        if self.api_base_url.query or self.api_base_url.fragment:
            raise ValueError(
                "RansomLook API base URL must not contain a query or fragment"
            )
        if self.api_key is not None and self.api_base_url.scheme != "https":
            raise ValueError("RansomLook API keys require an HTTPS base URL")
        artifact_producers_enabled = any(
            (
                self.import_post_evidence,
                self.import_location_evidence,
                self.import_notes,
                self.import_torrents,
                self.import_analyses,
            )
        )
        if artifact_producers_enabled:
            required_generic_mb = (4 * self.max_artifact_size_mb + 2) // 3 + 8
            if self.max_bundle_size_mb < required_generic_mb:
                raise ValueError(
                    "RANSOMLOOK_MAX_BUNDLE_SIZE_MB is too small for the "
                    "configured Artifact size"
                )
        if self.import_post_evidence:
            representation_factor_thirds = (
                12 if self.max_artifacts_per_claim == 1 else 20
            )
            required_bundle_mb = (
                representation_factor_thirds * self.max_artifact_size_mb + 2
            ) // 3 + 8
            if self.max_bundle_size_mb < required_bundle_mb:
                raise ValueError(
                    "RANSOMLOOK_MAX_BUNDLE_SIZE_MB is too small for the configured "
                    "post-evidence size"
                )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Load OpenCTI, connector, and RansomLook settings from supported sources."""

    model_config = ConfigDict(hide_input_in_errors=True, extra="ignore")

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ransomlook: RansomLookConfig = Field(default_factory=RansomLookConfig)

    def __init__(self, **data):
        """Reject misspelled source environment variables without their values."""
        allowed = {
            f"RANSOMLOOK_{name.upper()}" for name in RansomLookConfig.model_fields
        }
        unknown = sorted(
            name
            for name in os.environ
            if name.startswith("RANSOMLOOK_") and name not in allowed
        )
        if unknown:
            raise ValueError(
                "Unknown RansomLook environment variable(s): " + ", ".join(unknown)
            )
        super().__init__(**data)
