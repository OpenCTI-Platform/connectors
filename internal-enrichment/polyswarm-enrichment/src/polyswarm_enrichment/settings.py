"""Configuration for the PolySwarm Enrichment connector.

Uses connectors_sdk base classes for Pydantic-validated configuration.
All values are read from environment variables or config.yml.sample.
"""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
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
    community: str = Field(
        default="default",
        description="PolySwarm community ('default' or 'private' for dual-community).",
    )

    # TLP + score
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
        "",
    ] = Field(
        default="",
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
        default=["StixFile", "Artifact"],
        description="The scope of the connector.",
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
