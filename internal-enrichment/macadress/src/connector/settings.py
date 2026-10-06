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
        default="3dc00c31-f8f4-470b-bfb4-35a11ccd5c75",
    )
    name: str = Field(
        description="The name of the connector.",
        default="macadress.com",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["mac-addr"],
    )


class MacadressConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        description="macadress.com API base URL.",
        default="https://api.macadress.com",
    )
    api_key: SecretStr = Field(
        description="macadress.com API key (Bearer token, starts with 'mk_').",
    )
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
        default=30,
    )
    create_note: bool = Field(
        description="Create a note holding the full MAC address analysis summary.",
        default=True,
    )
    create_vendor_identity: bool = Field(
        description=(
            "Create an Organization identity for the IEEE-registered vendor and "
            "link the observable to it with a related-to relationship."
        ),
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    macadress: MacadressConfig = Field(default_factory=MacadressConfig)
