"""Urlscan connector settings"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr
from pydantic.json_schema import SkipJsonSchema

__all__ = [
    "ConnectorSettings",
]


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Extend the base external-import connector config with Urlscan's connector-level fields.

    The connector schedules itself through its own ``ConnectorLoop`` (see ``loop.py``),
    so the standard ``duration_period`` is disabled and the legacy ``interval`` /
    ``lookback`` fields are preserved as-is.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Urlscan",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'urlscan'.",
        default=["urlscan"],
    )
    interval: int = Field(
        description="Interval between two runs of the connector, in seconds.",
        default=86400,
    )
    lookback: int = Field(
        description=(
            "How far to look back in days if the connector has never run "
            "or its last run is older than this value."
        ),
        default=3,
    )
    # Override `duration_period` as scheduling is handled by the connector's own loop.
    duration_period: SkipJsonSchema[None] = Field(
        description="Do not use. Scheduling is handled by the connector's own loop.",
        default=None,
    )


class UrlscanConfig(BaseConfigModel):
    """Config fields specific to the Urlscan connector (mirror of the existing variables)."""

    url: HttpUrl = Field(
        description="The Urlscan feed URL to query.",
        default=HttpUrl("https://urlscan.io/api/v1/pro/phishfeed?format=json"),
    )
    api_key: SecretStr = Field(
        description="The Urlscan API key.",
    )
    create_indicators: bool = Field(
        description="Whether to create indicators for imported observables.",
        default=True,
    )
    update_existing_data: bool = Field(
        description="Whether to update data already ingested into the platform.",
        default=True,
    )
    default_tlp: str = Field(
        description="Default TLP marking applied to imported data.",
        default="white",
    )
    default_x_opencti_score: int = Field(
        description="Default x_opencti_score applied to imported data.",
        default=50,
    )
    x_opencti_score_domain: int | None = Field(
        description="Optional x_opencti_score for domain-name observables.",
        default=None,
    )
    x_opencti_score_url: int | None = Field(
        description="Optional x_opencti_score for url observables.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Urlscan connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlscan: UrlscanConfig = Field(default_factory=UrlscanConfig)
