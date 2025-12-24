from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="The ID of the connector.",
        default="496df155-c2f0-43b3-ab46-4352e68989d8",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Urlscan Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector. "
        "Availables: `url or hostname or domain-name` (scope-submission), `ipv4-addr` and `ipv6-addr` (scope-search)",
        default=["url", "ipv4-addr", "ipv6-addr"],
    )


class UrlscanEnrichmentConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlscanEnrichmentConnector`.
    """

    api_key: SecretStr = Field(
        description="URLScan API Key",
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
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Do not send any data to URLScan if the TLP of the observable is greater than MAX_TLP",
        default="TLP:AMBER",
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
