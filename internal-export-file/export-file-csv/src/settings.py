from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExportFileCsvConnectorConfig(BaseInternalExportFileConnectorConfig):
    """Connector-section configuration for the Export File CSV connector.

    Overrides the SDK defaults with the connector's own identity and scope.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="177c0a43-9dfe-4350-9706-040e12414d11",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ExportFileCsv",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the MIME type of the exported files.",
        default=["text/csv"],
    )


class ExportFileCsvConfig(BaseConfigModel):
    """Export File CSV specific configuration.

    Mirror of the existing `export-file-csv` variables.
    """

    delimiter: str = Field(
        description="The delimiter character used to separate the values in the exported CSV files.",
        default=";",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the Export File CSV connector."""

    connector: ExportFileCsvConnectorConfig = Field(
        default_factory=ExportFileCsvConnectorConfig
    )
    export_file_csv: ExportFileCsvConfig = Field(default_factory=ExportFileCsvConfig)
