# -*- coding: utf-8 -*-
"""Typed connector settings (connectors-sdk BaseConnectorSettings)."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator

SUPPORTED_SCOPE_ENTITY_TYPES = frozenset({"Email-Addr"})


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults for the INTERNAL_ENRICHMENT connector block."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="c6b0f5f2-c47e-4d49-92a9-10371b40f5d8",
        min_length=1,
    )
    name: str = Field(
        description="The name of the connector.",
        default="XposedOrNot",
    )
    scope: ListFromString = Field(
        description="The scope of the connector (observable types to enrich).",
        default=["Email-Addr"],
    )

    @field_validator("scope", mode="after")
    @classmethod
    def _scope_must_be_supported(cls, value: list[str]) -> list[str]:
        unsupported = [
            entry for entry in value if entry not in SUPPORTED_SCOPE_ENTITY_TYPES
        ]
        if unsupported:
            raise ValueError(
                f"Unsupported CONNECTOR_SCOPE entries: {unsupported}. This"
                f" connector only enriches"
                f" {sorted(SUPPORTED_SCOPE_ENTITY_TYPES)}."
            )
        return value

    auto: bool = Field(
        description=(
            "Enables or disables automatic enrichment of observables. The keyless"
            " community API is rate limited (2/s, 25/hour per IP); keep disabled or"
            " configure an API key before enabling on busy platforms."
        ),
        default=False,
    )


class XposedOrNotConfig(BaseConfigModel):
    """Configuration specific to the XposedOrNot connector."""

    api_key: SecretStr | None = Field(
        description=(
            "Optional XposedOrNot API key (console.xposedornot.com). When set, the"
            " connector uses the commercial Plus API with higher rate limits. The"
            " connector is fully functional without it."
        ),
        default=None,
    )
    api_base_url: HttpUrl = Field(
        description=(
            "Base URL of the free XposedOrNot community API. Must use https:"
            " the observable's email address is sent to this endpoint. It does"
            " not affect the Plus API, whose endpoint is fixed and is used"
            " instead whenever XPOSEDORNOT_API_KEY is set."
        ),
        default="https://api.xposedornot.com",
        json_schema_extra={"pattern": "^https://"},
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
    max_note_breaches: int = Field(
        description=(
            "Maximum number of breaches rendered in the summary note's table,"
            " newest first. A line names how many more were found. Set 0 to"
            " render every breach; large values make the note hard to read."
        ),
        default=50,
        ge=0,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description=(
                "Minimum Traffic Light Protocol (TLP) level applied to the"
                " objects imported into OpenCTI. The note carries the stricter"
                " of this level and the source observable's own marking."
                " Results contain personal data; a restrictive TLP is"
                " recommended. 'white' is the deprecated alias of 'clear'."
            ),
            default="amber",
        )
    )

    @field_validator("api_base_url", mode="after")
    @classmethod
    def _require_https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError(
                "api_base_url must use https; the observable's email address is"
                " sent to this endpoint and must not travel unencrypted."
            )
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Override BaseConnectorSettings with the connector-specific config blocks."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    xposedornot: XposedOrNotConfig = Field(default_factory=XposedOrNotConfig)
