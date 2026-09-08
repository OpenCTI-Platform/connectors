# -*- coding: utf-8 -*-
"""Typed connector settings (connectors-sdk BaseConnectorSettings)."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults for the INTERNAL_ENRICHMENT connector block."""

    name: str = Field(
        description="The name of the connector.",
        default="XposedOrNot",
    )
    scope: ListFromString = Field(
        description="The scope of the connector (observable types to enrich).",
        default=["Email-Addr"],
    )


class XposedOrNotConfig(BaseConfigModel):
    """Configuration specific to the XposedOrNot connector."""

    api_key: SecretStr | None = Field(
        description=(
            "Optional XposedOrNot API key (console.xposedornot.com). When set, the"
            " connector uses the higher-limit Plus API. Fully functional without it."
        ),
        default=None,
    )
    api_base_url: HttpUrl = Field(
        description="Base URL of the free XposedOrNot community API.",
        default="https://api.xposedornot.com",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description=(
            "Maximum TLP of an observable the connector is allowed to enrich. The"
            " observable's email address is sent to the XposedOrNot API."
        ),
        default="TLP:AMBER",
    )
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        description=(
            "TLP marking applied to the objects imported into OpenCTI. Results"
            " contain personal data; a restrictive TLP is recommended."
        ),
        default="amber",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Override BaseConnectorSettings with the connector-specific config blocks."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    xposedornot: XposedOrNotConfig = Field(default_factory=XposedOrNotConfig)
