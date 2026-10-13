# -*- coding: utf-8 -*-
"""Configuration models and settings for the Lamis Network connector."""

from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector-level configuration for Lamis Network internal enrichment."""

    name: str = Field(
        description="The name of the connector.",
        default="Lamis Network IP Intelligence",
    )
    scope: ListFromString = Field(
        description="Supported observable entity types.",
        default=["IPv4-Addr", "IPv6-Addr"],
    )
    auto: bool = Field(
        description="Whether the connector should automatically enrich incoming observables.",
        default=False,
    )


class LamisNetworkConfig(BaseConfigModel):
    """Lamis Network API and enrichment settings."""

    api_key: SecretStr = Field(
        description="Lamis Network API key for authentication.",
        min_length=1,
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key_non_empty(cls, v: SecretStr) -> SecretStr:
        """Ensure API key is not empty or pure whitespace."""
        if not v.get_secret_value().strip():
            raise ValueError("Lamis Network API key must not be empty.")
        return v

    api_url: HttpUrl = Field(
        description="Lamis Network API base URL.",
        default="https://api.lamisnetwork.com",
    )
    timeout: int = Field(
        description="HTTP request timeout in seconds.",
        default=10,
        ge=1,
    )
    suspicious_threshold: int = Field(
        description="Fraud score threshold (0-100) above which observable is tagged suspicious.",
        default=75,
        ge=0,
        le=100,
    )
    create_indicator: bool = Field(
        description="Whether to generate high-risk STIX Indicators.",
        default=True,
    )
    add_relationships: bool = Field(
        description="Whether to create belongs-to and located-at STIX relationships.",
        default=True,
    )
    default_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Default TLP marking applied when observable carries no explicit marking.",
        default="TLP:CLEAR",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP level of observables this connector will enrich. Observables with higher TLP are skipped.",
        default="TLP:AMBER",
    )

    @field_validator("default_tlp", "max_tlp", mode="before")
    @classmethod
    def _normalize_tlp_field(cls, value: Any) -> str:
        if not value or not isinstance(value, str):
            return "TLP:CLEAR"
        normalized = value.strip().upper()
        if not normalized.startswith("TLP:"):
            normalized = f"TLP:{normalized}"
        return normalized


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings combining base connector config with Lamis Network config."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    lamis_network: LamisNetworkConfig = Field(default_factory=LamisNetworkConfig)
