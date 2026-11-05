from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector-level settings for the WhoisFreaks enrichment connector."""

    name: str = Field(
        description="The name of the connector.",
        default="WhoisFreaks",
    )
    scope: ListFromString = Field(
        description="The observable types the connector enriches.",
        default=["Domain-Name"],
    )
    auto: bool = Field(
        description=(
            "Enrich new observables automatically. Every lookup spends API credits, "
            "so this is off by default."
        ),
        default=False,
    )
    max_tlp: TLPLevel = Field(
        description=(
            "Highest TLP of the observables the connector sends to WhoisFreaks. "
            "Observables marked above it are skipped."
        ),
        default=TLPLevel.AMBER_STRICT,
    )


class WhoisFreaksConfig(BaseConfigModel):
    """Settings specific to WhoisFreaks."""

    api_key: SecretStr = Field(
        description="WhoisFreaks API key.",
        min_length=1,
    )
    api_base_url: HttpUrl = Field(
        description="WhoisFreaks API base URL.",
        default="https://api.whoisfreaks.com",
    )
    timeout: int = Field(
        description="HTTP request timeout in seconds.",
        default=30,
        ge=1,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to the objects the connector creates.",
        default=TLPLevel.CLEAR,
    )
    create_labels: bool = Field(
        description="Add labels to the observable, such as the registrar and DNSSEC status.",
        default=True,
    )
    create_relationships: bool = Field(
        description=(
            "Link the observable to its registrar, name servers and registrant "
            "email and organization."
        ),
        default=True,
    )
    create_note: bool = Field(
        description="Attach a note with the full WHOIS report to the observable.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the WhoisFreaks connector, read from environment variables or `config.yml`."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    whoisfreaks: WhoisFreaksConfig = Field(default_factory=WhoisFreaksConfig)
