from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override BaseInternalImportFileConnectorConfig to add defaults for ImportDocument."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="b4cc8d6b-1e61-4dc9-8aa1-5e494e6f8d5a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ImportDocument",
    )
    type: Literal["INTERNAL_IMPORT_FILE", "INTERNAL_ANALYSIS"] = Field(
        description=(
            "The type of the connector. Use `INTERNAL_ANALYSIS` to run the connector "
            "in content mapping mode, along with `only_contextual` set to `true`."
        ),
        default="INTERNAL_IMPORT_FILE",
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
    only_contextual: bool = Field(
        description="If `true`, only extract data when an entity context is provided.",
        default=False,
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
    import_document: ImportDocumentConfig = Field(default_factory=ImportDocumentConfig)
