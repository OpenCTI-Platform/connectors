from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="UrlscanEnrichment",
    )


class UrlscanEnrichmentConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlscanEnrichmentConnector`.
    """

    api_key: SecretStr = Field(
        description="URLScan API Key",
    )
    api_base_url: str = Field(
        description="URLScan Base Url",
    )
    import_screenshot: bool = Field(
        description="Allows or not the import of the screenshot of the scan submitted in URLScan to OpenCTI.",
        default=True,
    )
    visibility: Literal["public", "unlisted", "private"] = Field(
        description="URLScan offers several levels of visibility for submitted scans: `public`, `unlisted`, `private`",
        default="public",
    )
    search_filtered_by_date: str = Field(
        description="Allows you to filter by date available: `>now-1h`, `>now-1d`, `>now-1y`, `[2022 TO 2023]`, `[2022/01/01 TO 2023/12/01]`",
        default=">now-1y",
    )
    max_tlp: str = Field(
        description="Do not send any data to URLScan if the TLP of the observable is greater than MAX_TLP",
    )
    create_indicator: bool = Field(
        description="Decide whether or not to create an indicator based on this observable",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `UrlscanEnrichmentConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    urlscan_enrichment: UrlscanEnrichmentConfig = Field(
        default_factory=UrlscanEnrichmentConfig
    )
