from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 identifying the connector.",
        default="64750c1e-91f0-41db-a8a8-cb2228874be2",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Report Article Fetcher",
    )
    scope: ListFromString = Field(
        description="The entity types the connector enriches.",
        default=["Report"],
    )


class ReportArticleFetcherConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ReportArticleFetcherConnector`.
    """

    user_agent: str = Field(
        description="User-Agent sent when fetching article pages.",
        default="OpenCTI Report Article Fetcher",
    )
    request_timeout: int = Field(
        description="Timeout of one page request, in seconds.",
        default=20,
        gt=0,
    )
    max_download_size: int = Field(
        description="Largest page downloaded, in bytes.",
        default=5_000_000,
        gt=0,
    )
    min_length: int = Field(
        description="Shortest extracted article accepted, in characters of text.",
        default=500,
        ge=0,
    )
    length_ratio: float = Field(
        description="The article must be this many times longer than the report's current text.",
        default=1.5,
        ge=1,
    )
    min_title_similarity: float = Field(
        description=(
            "Lowest match accepted between the report name and the page (0 to 1): "
            "page title, words of the name at the top of the text, or URL slug."
        ),
        default=0.6,
        ge=0,
        le=1,
    )
    follow_pdf: bool = Field(
        description=(
            "On a landing page (a short page that links its report as a PDF on the "
            "same site), also fetch the PDF: its text follows the page in the report's "
            "content and the file is attached to the report."
        ),
        default=True,
    )
    landing_max_length: int = Field(
        description=(
            "A page whose extracted text is shorter than this, in characters, is a "
            "landing page whose linked PDF report is followed."
        ),
        default=4000,
        ge=0,
    )
    max_pdf_size: int = Field(
        description="Largest PDF report downloaded from a landing page, in bytes.",
        default=20_000_000,
        gt=0,
    )
    match_single_reference: bool = Field(
        description=(
            "Also accept reports not created by the RSS ingestion when they have exactly "
            "one external reference."
        ),
        default=False,
    )
    max_workers: int = Field(
        description=(
            "Reports processed at the same time by one connector process. Each worker "
            "consumes the queue with its own OpenCTI client and HTTP session, like a "
            "replica of the connector. Requires the AMQP listen protocol."
        ),
        default=1,
        ge=1,
        le=32,
    )
    summary_log_level: Literal["debug", "info", "warning", "error", "none"] = Field(
        description=(
            "Level of the one-line summary written for each report (outcome, skip "
            "reason, fetch, extraction, check and send times). The default is "
            "visible under the default log level; none turns it off."
        ),
        default="error",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `ReportArticleFetcherConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    report_article_fetcher: ReportArticleFetcherConfig = Field(
        default_factory=ReportArticleFetcherConfig
    )
