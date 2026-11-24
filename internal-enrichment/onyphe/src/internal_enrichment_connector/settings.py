"""OpenCTI ONYPHE connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class OnypheConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for the ONYPHE connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5d5d8a0c-029d-40ed-a711-371b664c43e6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ONYPHE",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "ipv4-addr",
            "ipv6-addr",
            "indicator",
            "hostname",
            "x509-certificate",
            "text",
        ],
    )


class OnypheConfig(BaseConfigModel):
    """Settings specific to the ONYPHE connector."""

    api_key: SecretStr = Field(
        description="The ONYPHE API key.",
    )
    base_url: str = Field(
        description="The ONYPHE API base URL (with a trailing slash).",
        default="https://www.onyphe.io/api/v2/",
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description="The maximal TLP of the entities to enrich.",
    )
    category: str = Field(
        description="The ONYPHE data category to query: `ctiscan` or `riskscan`.",
        default="ctiscan",
    )
    time_since: str = Field(
        description="The time window of the ONYPHE data to retrieve (OQL `-since` value, e.g. `1w`).",
        default="1w",
    )
    default_score: int = Field(
        description="The default score of the created observables.",
        default=50,
    )
    import_search_results: bool = Field(
        description="Whether to import the search results as observables when enriching an indicator.",
        default=True,
    )
    create_note: bool = Field(
        description="Whether to attach the enrichment summary as a note on observables, instead of their description.",
        default=False,
    )
    import_full_data: bool = Field(
        description="Whether to import the full raw application response text (can produce large data).",
        default=False,
    )
    pivot_threshold: int = Field(
        description="The maximum number of results of an observable enrichment: above it, nothing is imported.",
        default=10,
    )
    indicator_max_results: int = Field(
        description=(
            "The maximum number of results of an indicator enrichment: "
            "above it, the query is considered too imprecise and nothing is imported."
        ),
        default=1000,
    )
    pattern_type: str = Field(
        description="The vocabulary entry of the ONYPHE indicator pattern type.",
        default="onyphe",
    )
    enrichment_types: ListFromString = Field(
        description=(
            "Comma-separated list of OpenCTI object types to create during enrichment, "
            "empty for all types. Valid values: Domain-Name, Hostname, IPv4-Address, "
            "IPv6-Address, Autonomous-System, X509-Certificate, Text, Vulnerability."
        ),
        default=[],
    )
    text_fingerprints: ListFromString = Field(
        description=(
            "Comma-separated list of fingerprint pivot labels to create as Text "
            "observables, empty for the default sha256-preferred set "
            "(e.g. hhhash-sha256, favicon-sha256, ssh-fingerprint-sha256)."
        ),
        default=[],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the ONYPHE connector."""

    connector: OnypheConnectorConfig = Field(default_factory=OnypheConnectorConfig)
    onyphe: OnypheConfig = Field(default_factory=OnypheConfig)
