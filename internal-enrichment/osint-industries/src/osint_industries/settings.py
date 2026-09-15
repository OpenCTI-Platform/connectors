# -*- coding: utf-8 -*-
"""Pydantic settings for the OSINT Industries enrichment connector.

The models below mirror 1:1 the configuration variables historically resolved
with `pycti.get_config_variable` (`OSINT_INDUSTRIES_*` env vars or the
`osint_industries` section of `config.yml`).
"""

from __future__ import annotations

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class OsintIndustriesConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Override `BaseInternalEnrichmentConnectorConfig` with this connector's defaults."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="cef186b0-eb77-41d4-8fc5-cc8739eafa2a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="OSINT Industries",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the observable types it can enrich.",
        default=[
            "Email-Addr",
            "Phone-Number",
            "User-Account",
            "Cryptocurrency-Wallet",
        ],
    )


class OsintIndustriesConfig(BaseConfigModel):
    """Configuration specific to the OSINT Industries connector."""

    api_key: SecretStr = Field(
        description="The API key used to authenticate against the OSINT Industries API.",
    )
    base_url: HttpUrl = Field(
        description="The base URL of the OSINT Industries API.",
        default=HttpUrl("https://api.osint.industries"),
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="The TLP marking applied to the objects produced by the connector.",
        default="amber+strict",
    )
    premium: bool = Field(
        description=(
            "Whether to query the premium modules. "
            "Enabling it returns more results but consumes more API credits."
        ),
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override `BaseConnectorSettings` with the OSINT Industries configurations."""

    connector: OsintIndustriesConnectorConfig = Field(
        default_factory=OsintIndustriesConnectorConfig
    )
    osint_industries: OsintIndustriesConfig = Field(
        default_factory=OsintIndustriesConfig  # type: ignore[arg-type]
    )
