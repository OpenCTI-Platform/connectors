"""Connector configuration.

Values come from environment variables or ``config.yml``. Environment
variables win. The Cyble-specific section is ``cyble_vision`` /
``CYBLE_VISION_*``.
"""

from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """OpenCTI-level options for this connector."""

    id: str = Field(
        description="Unique connector ID. Generate a UUIDv4 and keep it stable.",
        default="7c2e8a4f-3b91-4d6e-9f12-a8c5e1d0b473",
    )
    name: str = Field(
        description="Display name in OpenCTI.",
        default="Cyble Vision",
    )
    scope: ListFromString = Field(
        description="Descriptive entity types this connector imports.",
        default=[
            "Incident",
            "Report",
            "Note",
            "Indicator",
            "Vulnerability",
            "Intrusion-Set",
            "Domain-Name",
            "IPv4-Addr",
            "Url",
            "X509-Certificate",
            "User-Account",
        ],
    )
    duration_period: timedelta = Field(
        description="Wait time between runs, as an ISO-8601 duration.",
        default=timedelta(hours=1),
    )


class CybleVisionConfig(BaseConfigModel):
    """Credentials and filters for the Cyble Vision Alerts API."""

    api_base_url: HttpUrl = Field(
        description="Cyble Vision API base URL.",
        default="https://bifrost.cyble.ai",
    )
    api_token: SecretStr = Field(
        description="Cyble Vision API bearer token.",
    )
    import_since: DatetimeFromIsoString = Field(
        description="Lookback on the first run. Absolute ISO datetime or relative duration such as P7D.",
        default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=7),
    )
    alert_services: ListFromString = Field(
        description="Allow-list of Vision service names. Empty means every entitled service from GET /y/services.",
        default=[],
        examples=["ssl_expiry,darkweb_data_breaches,advisory,flash_report"],
    )
    exclude_statuses: ListFromString = Field(
        description="Alert statuses to omit from import.",
        default=["FALSE_POSITIVE"],
    )
    page_size: int = Field(
        description="Alerts API page size (skip/take).",
        default=100,
        ge=1,
        le=500,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every imported object.",
        default=TLPLevel.AMBER,
    )
    portal_url_template: str = Field(
        description="Deep-link template. Placeholders: {service}, {alert_id}.",
        default='https://cyble.ai/alerts/{service}?id=["{alert_id}"]',
    )
    engine_api_base_url: HttpUrl = Field(
        description="Cyble engine API base URL for advisories, newsfeed, and newsflash.",
        default="https://api.cyble.ai",
    )
    enable_advisories: bool = Field(
        description="Import research advisories from the engine API.",
        default=True,
    )
    enable_newsfeed: bool = Field(
        description="Import newsfeed articles from the engine API.",
        default=True,
    )
    enable_newsflash: bool = Field(
        description="Import newsflash spot reports from the engine API.",
        default=True,
    )
    engine_page_size: int = Field(
        description="Page size for engine document APIs.",
        default=50,
        ge=1,
        le=200,
    )


class ConnectorSettings(BaseConnectorSettings):
    """All configuration sections this connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    cyble_vision: CybleVisionConfig = Field(default_factory=CybleVisionConfig)
