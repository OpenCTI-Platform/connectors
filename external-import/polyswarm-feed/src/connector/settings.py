"""Connector configuration models.

Two groups of options:

    - `ExternalImportConnectorConfig`: options common to every connector of
      type `EXTERNAL_IMPORT` (from `connectors-sdk`), with defaults for this
      connector.
    - `PolySwarmFeedConfig`: options specific to this connector, exposed
      under the `polyswarm` key, so environment variables are `POLYSWARM_*`.
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr, field_validator

# TAXII 2.1 API roots served by PolySwarm, by the name used in the settings.
SUPPORTED_FEED_COLLECTIONS = ("trustgroup", "ransomware", "freemium")


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, with defaults for this connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ec7c0432-95ab-4896-899c-a1aca2c91997",
    )
    name: str = Field(
        description="The name of the connector.",
        default="PolySwarm Feed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the types it imports.",
        default=[
            "Malware",
            "Indicator",
            "StixFile",
            "Malware-Analysis",
            "Attack-Pattern",
            "Note",
        ],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour).",
        default=timedelta(hours=1),
    )


class PolySwarmFeedConfig(BaseConfigModel):
    """Configuration specific to the PolySwarm feed connector."""

    # --- API connection ---
    api_key: SecretStr = Field(
        description="PolySwarm API key. Used as the TAXII Basic auth password "
        "and for the live hunting API.",
    )
    account_number: str = Field(
        description="PolySwarm account number. Used as the TAXII Basic auth username.",
        min_length=1,
    )
    api_url: str = Field(
        description="PolySwarm API base URL. The connector appends the `/v3/...` paths.",
        default="https://api.polyswarm.network",
    )

    # --- TAXII feed ---
    feed_collections: ListFromString = Field(
        description="Comma-separated list of PolySwarm TAXII API roots to import. "
        "Allowed values: trustgroup, ransomware, freemium.",
        default=["trustgroup"],
    )
    feed_backfill_days: int = Field(
        description="On the first run only, how many days of feed data to import.",
        default=14,
        ge=1,
    )
    feed_indicator_valid_days: int = Field(
        description="Feed indicators are valid until import time plus this many days.",
        default=90,
        ge=1,
    )

    # --- Live hunting ---
    hunting_enabled: bool = Field(
        description="Import live hunting results (YARA rule matches) of the account.",
        default=False,
    )
    hunting_backfill_hours: int = Field(
        description="On the first run only, how many hours of live hunting results to import.",
        default=24,
        ge=1,
    )
    hunting_indicator_valid_days: int = Field(
        description="Live hunting indicators are valid until import time plus this many days.",
        default=30,
        ge=1,
    )

    # --- Import behaviour ---
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object the connector sends.",
        default=TLPLevel.CLEAR,
    )
    max_objects_per_run: int = Field(
        description="Stop paging once this many objects were sent in a run. "
        "The next run resumes where this one stopped.",
        default=20000,
        ge=1,
    )

    @field_validator("feed_collections")
    @classmethod
    def _validate_feed_collections(cls, value: list[str]) -> list[str]:
        """Normalize the collection names, reject unknown ones and duplicates."""
        collections: list[str] = []
        for name in value:
            normalized = name.strip().lower()
            if normalized not in SUPPORTED_FEED_COLLECTIONS:
                raise ValueError(
                    f"Unknown feed collection '{name}'. "
                    f"Allowed values: {', '.join(SUPPORTED_FEED_COLLECTIONS)}."
                )
            if normalized not in collections:
                collections.append(normalized)
        if not collections:
            raise ValueError("At least one feed collection must be configured.")
        return collections

    @field_validator("api_url")
    @classmethod
    def _strip_api_url(cls, value: str) -> str:
        """Drop a trailing slash so paths can be appended safely."""
        return value.rstrip("/")


class ConnectorSettings(BaseConnectorSettings):
    """All configuration objects the connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    polyswarm: PolySwarmFeedConfig = Field(default_factory=PolySwarmFeedConfig)
