from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, PositiveInt, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """`INTERNAL_ENRICHMENT` connector config with IntelOwl defaults."""

    name: str = Field(
        description="The name of the connector.",
        default="IntelOwl",
    )
    scope: ListFromString = Field(
        description="The observable types the connector enriches.",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Hostname",
            "Url",
            "StixFile",
        ],
    )


class IntelOwlConfig(BaseConfigModel):
    """IntelOwl-specific configuration (env prefix `INTELOWL_`)."""

    url: HttpUrl = Field(
        description="Base URL of the IntelOwl instance, e.g. `https://intelowl.example.com`.",
    )
    api_key: SecretStr = Field(
        description="IntelOwl API key (created under 'API Access' in IntelOwl).",
    )
    playbook: str = Field(
        description="IntelOwl playbook to run on each observable. The default only uses analyzers that need no third-party API key.",
        default="FREE_TO_USE_ANALYZERS",
    )
    verify_ssl: bool = Field(
        description="Verify the TLS certificate of the IntelOwl instance.",
        default=True,
    )
    poll_interval: PositiveInt = Field(
        description="Seconds between two checks of a running IntelOwl job.",
        default=5,
    )
    job_timeout: PositiveInt = Field(
        description="Seconds to wait for an IntelOwl job to finish before giving up.",
        default=300,
    )
    update_score: bool = Field(
        description="Set the observable score from IntelOwl's verdict (malicious: reliability x 10, trusted: 0).",
        default=True,
    )
    create_labels: bool = Field(
        description="Add IntelOwl's tags and malware family as labels on the observable.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the IntelOwl connector."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    intelowl: IntelOwlConfig = Field(default_factory=IntelOwlConfig)
