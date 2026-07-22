"""Configuration models for the Dark Web Informer connector (passthrough mode)."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class _ConnectorConfig(BaseExternalImportConnectorConfig):
    """Base connector configuration with Dark Web Informer defaults."""

    id: str = Field(
        description="The unique UUIDv4 identifier for this connector instance.",
        examples=["d1c5e2a7-0b3f-4e8a-9c6d-7f2b1a4e9c30"],
    )
    name: str = Field(
        default="Dark Web Informer",
        description="The name of the connector.",
        examples=["Dark Web Informer"],
    )
    scope: ListFromString = Field(
        default=["dark-web-informer"],
        description="The scope of the connector.",
        examples=["dark-web-informer"],
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=6),
        description="ISO-8601 duration between two runs of the connector.",
        examples=["PT6H"],
    )


class DarkWebInformerConfig(BaseConfigModel):
    """Configuration specific to the Dark Web Informer connector."""

    base_url: HttpUrl = Field(
        default="https://api.darkwebinformer.com",
        description="Base URL of the Dark Web Informer API.",
        examples=["https://api.darkwebinformer.com"],
    )
    api_key: SecretStr = Field(
        description="The Dark Web Informer API key, sent as the X-API-Key header.",
        examples=["your-dwi-api-key"],
    )
    sources: ListFromString = Field(
        default=["feed", "ransomware", "iocs"],
        description="Which prebuilt STIX bundles to ingest: feed, ransomware, iocs (or all).",
        examples=["feed,ransomware,iocs"],
    )
    use_preview_endpoint: bool = Field(
        default=False,
        description="Use the smaller on-demand /api/stix.json preview instead of the full bulk bundles (useful for testing).",
        examples=[False],
    )
    preview_limit: int = Field(
        default=5000,
        description="Object limit when use_preview_endpoint is true (max 5000).",
        examples=[5000],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings for the Dark Web Informer connector."""

    connector: _ConnectorConfig
    dark_web_informer: DarkWebInformerConfig
