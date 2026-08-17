from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Connector section with defaults specific to Import File MISP."""

    name: str = Field(
        description="The name of the connector.",
        default="ImportExternalReference",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5cb8badc-28c0-404a-8ecd-cfba227050b5",
    )
    scope: ListFromString = Field(
        description="The scope (MIME types) handled by the connector.",
        default=["External-Reference"],
    )


class ImportExternalReferenceConfig(BaseConfigModel):
    """Config fields specific to the Import External Reference connector.

    Mirror of the connector's existing configuration variables.
    """

    import_as_pdf: bool = Field(
        description="Import external references as PDF files.",
        default=True,
    )
    import_as_md: bool = Field(
        description="Import external references as MarkDown files.",
        default=True,
    )
    import_pdf_as_md: bool = Field(
        description="If import_as_md is true, try to convert the PDF to Markdown.",
        default=True,
    )
    timestamp_files: bool = Field(
        description="If true, timestamp imported files to prevent overwriting versions.",
        default=False,
    )
    cache_size: int = Field(
        description="Size of the LRU URL cache to prevent fetching the same object repeatedly.",
        default=32,
    )
    cache_ttl: int = Field(
        description="Time-to-live (in seconds) for cache entries.",
        default=3600,
    )
    browser_worker_count: int = Field(
        description="Number of browser worker threads to use.",
        default=4,
    )
    max_download_size: int = Field(
        description="Maximum download size in bytes. (default: 50MB)",
        default=52428800,  # 50 * 1024 * 1024
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    import_external_reference: ImportExternalReferenceConfig = Field(
        default_factory=ImportExternalReferenceConfig
    )
