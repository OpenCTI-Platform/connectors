"""Typed settings of the NetAPI connector (connectors-sdk BaseConnectorSettings)."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator

SUPPORTED_SCOPE_ENTITY_TYPES = frozenset(
    {"Domain-Name", "Hostname", "IPv4-Addr", "Url"}
)
TLPLevel = Literal["clear", "white", "green", "amber", "amber+strict", "red"]


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector-level settings of the NetAPI enrichment connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6f0b6c2e-9f6e-4d2a-8a6b-3c0f4b2d9e71",
        min_length=1,
    )
    name: str = Field(
        description="The name of the connector.",
        default="NetAPI",
    )
    scope: ListFromString = Field(
        description="The observable types the connector enriches.",
        default=["Domain-Name", "Hostname", "IPv4-Addr", "Url"],
    )
    auto: bool = Field(
        description=(
            "Enrich new observables automatically. Without an API token the NetAPI "
            "JSON API allows 30 requests a minute and 1,000 a day per IP address, so "
            "this is off by default."
        ),
        default=False,
    )

    @field_validator("scope", mode="after")
    @classmethod
    def _scope_must_be_supported(cls, value: list[str]) -> list[str]:
        unsupported = [v for v in value if v not in SUPPORTED_SCOPE_ENTITY_TYPES]
        if unsupported:
            raise ValueError(
                f"Unsupported CONNECTOR_SCOPE entries: {unsupported}. This connector "
                f"only enriches {sorted(SUPPORTED_SCOPE_ENTITY_TYPES)}."
            )
        return value


class NetAPIConfig(BaseConfigModel):
    """Settings specific to NetAPI."""

    api_token: SecretStr | None = Field(
        description=(
            "Optional NetAPI API token (the token of any account, free accounts "
            "included). The lookups are free without one; a token only raises the "
            "request limits."
        ),
        default=None,
    )
    api_base_url: HttpUrl = Field(
        description="Base URL of the NetAPI JSON API.",
        default="https://netapi.com/api-json/",
    )
    timeout: int = Field(
        description="HTTP request timeout in seconds.",
        default=30,
        ge=1,
    )
    include_rank: bool = Field(
        description=(
            "Add the position of a listed domain in the NetAPI Top 1M to the note "
            "(one more request per listed domain or hostname)."
        ),
        default=True,
    )
    update_score: bool = Field(
        description=(
            "Write `score` to the observable when it is listed in the compromised "
            "feed now. The existing score is overwritten. Off by default."
        ),
        default=False,
    )
    score: int = Field(
        description="Score written to a currently listed observable when `update_score` is true.",
        default=80,
        ge=0,
        le=100,
    )
    tlp_level: TLPLevel = Field(
        description=(
            "TLP marking applied to the note, in addition to the markings of the "
            "source observable. The feed is public data (CC BY 4.0)."
        ),
        default="clear",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the NetAPI connector, read from environment variables or `config.yml`."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    netapi: NetAPIConfig = Field(default_factory=NetAPIConfig)
