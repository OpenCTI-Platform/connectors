from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class _ConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        default="censys-collections--00000000-0000-0000-0000-000000000000",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Censys Collections",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "X509-Certificate",
            "Malware",
            "Threat-Actor-Group",
            "Vulnerability",
            "Indicator",
        ],
        description="The entity types this connector ingests into OpenCTI.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=1),
        description="How long to wait between two ingestion runs.",
    )


class _CensysCollectionsConfig(BaseConfigModel):
    organisation_id: SecretStr = Field(
        description="Censys organisation ID.",
    )
    token: SecretStr = Field(
        description="Censys API token.",
    )
    collection_ids: ListFromString | None = Field(
        default=None,
        description=(
            "Comma-separated list of Censys collection IDs to ingest. "
            "Leave empty to ingest all collections for the organisation. "
            "Takes precedence over 'excluded_collection_ids' if both are set."
        ),
    )
    excluded_collection_ids: ListFromString | None = Field(
        default=None,
        description=(
            "Comma-separated list of Censys collection IDs to exclude from "
            "ingestion; every other collection visible to the organisation is "
            "ingested. Ignored if 'collection_ids' is set."
        ),
    )
    tlp_level: Literal[
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:AMBER",
        description="TLP marking applied to all ingested observables and indicators.",
    )
    indicator_score: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Confidence score (0–100) assigned to ingested observables and indicators.",
    )
    auto_indicator_by_score: bool = Field(
        default=False,
        description=(
            "If enabled, an indicator is only auto-created for an observable "
            "when its score meets or exceeds 'indicator_score_threshold'. "
            "If disabled (default), an indicator is always auto-created for "
            "every ingested observable, regardless of score."
        ),
    )
    indicator_score_threshold: int = Field(
        default=50,
        ge=0,
        le=100,
        description=(
            "Minimum score (0–100) an observable must have for an indicator "
            "to be auto-created. Only used when 'auto_indicator_by_score' is "
            "enabled."
        ),
    )
    request_timeout_seconds: int = Field(
        default=60,
        ge=1,
        description=(
            "Per-request timeout (in seconds) for calls to the Censys API. "
            "Increase this if large collections cause read timeouts."
        ),
    )


class ConfigLoader(BaseConnectorSettings):
    connector: _ConnectorConfig = Field(  # type: ignore[assignment]
        default_factory=_ConnectorConfig,
        description="External Import Connector configurations.",
    )
    censys_collections: _CensysCollectionsConfig = Field(
        description="Censys Collections configurations.",
    )

    def __init__(self) -> None:
        """Load configuration from env vars/.env/config.yml (no arguments needed).

        Declared explicitly so Pyright doesn't synthesize a pydantic
        ``__init__`` requiring ``censys_collections`` as an argument (it has
        no default since it's populated from environment variables at
        runtime, not passed in by callers).
        """
        super().__init__()
