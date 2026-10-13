"""Urlscan connector settings"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr

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
    id: str = Field(
        description="The ID of the connector.",
        default="0247889a-84b9-4210-a719-b1037358c491",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'urlscan'.",
        default=["urlscan"],
    )
    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use duration_period instead",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(seconds=x),
    )
    lookback: int = Field(
        description=(
            "How far to look back in days if the connector has never run "
            "or its last run is older than this value."
        ),
        default=3,
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(seconds=86400),
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
    labels: ListFromString = Field(
        description="list of labels to apply to each observable.",
        default=["Phishing", "phishfeed"],
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Urlscan connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlscan: UrlscanConfig = Field(default_factory=UrlscanConfig)
