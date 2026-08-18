from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override BaseInternalImportFileConnectorConfig to add defaults for ImportDocument."""

    name: str = Field(
        description="The name of the connector.",
        default="ImportDocument",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "application/pdf",
            "text/plain",
            "text/csv",
            "text/html",
            "text/markdown",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ],
    )
    validate_before_import: bool = Field(
        description="Validate any bundle before import.",
        default=True,
    )


class ImportDocumentConfig(BaseConfigModel):
    """Config fields specific to the ImportDocument connector."""

    create_indicator: bool = Field(
        description="If true, creates an Indicator for each extracted observable.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ImportDocument connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_document: ImportDocumentConfig = Field(
        default_factory=ImportDocumentConfig
    )
