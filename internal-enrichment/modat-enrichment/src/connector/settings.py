from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    id: str = Field(
        description="The ID of the connector.",
        default="d2d7a7e3-4cb4-4f58-94c2-7bb6d2f8f643",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Modat Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ipv4-addr"],
    )


class ModatConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="Modat API base URL.",
        default="https://api.magnify.modat.io",
    )
    api_key: SecretStr = Field(description="Modat API key.")
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="The maximal TLP of the observable being enriched.",
        default="TLP:AMBER",
    )
    default_score: int = Field(
        description="Score to apply on the enriched observable.",
        default=50,
    )
    create_note: bool = Field(
        description="Create a note with raw Modat response summary.",
        default=True,
    )
    include_cves: bool = Field(
        description=(
            "Include CVE data from Modat (top-level and per-service) in the "
            "summary note and create STIX Vulnerability objects. Disabled by "
            "default because Modat-reported CVEs are not validated."
        ),
        default=False,
    )
    max_services_in_summary: int = Field(
        description="Maximum number of services rendered in the summary note.",
        default=25,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    modat: ModatConfig = Field(default_factory=ModatConfig)
