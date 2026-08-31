"""Typed configuration for the Intel 471 Hunter connector.

Values resolve in the order `ENV VAR` -> `config.yml` -> field default, handled
by connectors-sdk's `BaseConnectorSettings`. The nested field name sets the
environment-variable prefix, so `hunter.api_key` is `HUNTER_API_KEY`.
"""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr

DEFAULT_SCOPE = [
    # Types the connector emits. OpenCTI applies the scope as a type-filter on
    # the returned bundle, so omitting these silently discards them.
    "Report",
    "Indicator",
    "Note",
    # Types the connector can be triggered on.
    "Intrusion-Set",
    "Threat-Actor",
    "Threat-Actor-Group",
    "Threat-Actor-Individual",
    "Campaign",
    "Attack-Pattern",
    "Vulnerability",
    "Malware",
    "Tool",
    "Sector",
    "Country",
    "Region",
]


class HunterConfig(BaseConfigModel):
    """Connector-specific settings (`HUNTER_*`)."""

    api_base_url: HttpUrl = Field(
        description="Base URL of the Intel 471 Hunter API.",
        default=HttpUrl("https://api.hunter.cyborgsecurity.io"),
    )
    api_key: SecretStr = Field(
        description=(
            "Intel 471 Hunter API key, sent as `Authorization: API-Key <key>`. "
            "Obtained separately from Verity471/Titan credentials."
        ),
    )
    ui_base_url: HttpUrl | None = Field(
        description=(
            "Base URL of the Hunter UI, used to build external references back "
            "to each hunt. Leave empty to omit those links."
        ),
        default=HttpUrl("https://hunter.cyborgsecurity.io"),
    )
    indexes: str = Field(
        description="Hunter index to query.",
        default="cyborg_usecases",
    )
    request_timeout_seconds: int = Field(
        description="HTTP timeout, in seconds, for calls to the Hunter API.",
        default=30,
        gt=0,
    )
    max_results_per_query: int = Field(
        description="Maximum number of hunt packages retrieved per query.",
        default=100,
        gt=0,
    )
    cache_path: str = Field(
        description=(
            "Path of the local `(hunt_uuid, last_updated)` cache. Keep this on a "
            "dedicated directory: mounting a volume over the connector's working "
            "directory shadows its code."
        ),
        default="/opt/opencti-connector-intel471-hunt/cache/cache.json",
    )
    cache_ttl_hours: int = Field(
        description="Lifetime, in hours, of a cache entry.",
        default=24,
        gt=0,
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="The maximal TLP of the entity being enriched.",
        default="TLP:AMBER",
    )


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="Intel 471 Hunter",
    )
    scope: ListFromString = Field(
        description=(
            "Entity types the connector can be triggered on, plus every type it "
            "emits (Report, Indicator, Note) — OpenCTI drops unlisted types."
        ),
        default=DEFAULT_SCOPE,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    hunter: HunterConfig = Field(default_factory=HunterConfig)
