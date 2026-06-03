"""Configuration for the PolySwarm Sandbox connector.

Uses connectors_sdk base classes (Criminal IP / upstream pattern).
"""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
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
    timeout: int = Field(
        default=ps_settings.DEFAULT_HTTP_TIMEOUT,
        description="HTTP timeout for PolySwarm API calls in seconds.",
    )

    # TLP + score
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
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

    Scope is ``Artifact`` only: the sandbox detonates an uploaded file,
    so it needs the file attached to an Artifact. A StixFile observable
    carrying just a hash has nothing to detonate.
    """

    name: str = Field(
        default="PolySwarm Sandbox",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=["Artifact"],
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
