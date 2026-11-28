from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field

CONNECTOR_TYPE_BY_MODE = {
    "import": "INTERNAL_IMPORT_FILE",
    "analysis": "INTERNAL_ANALYSIS",
}


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
            "The type of the connector. `INTERNAL_ANALYSIS` runs the connector "
            "in content mapping mode. Ignored when `IMPORT_DOCUMENT_MODE` is set, "
            "which catalog deployments must use since they cannot set this value."
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
    mode: Literal["import", "analysis"] | None = Field(
        description=(
            "`import` registers the connector as a file import connector, which "
            "parses uploaded files into entities. `analysis` registers it as an "
            "analysis connector, used by 'Ask new mapping' in the Content tab of "
            "containers. Deploy one instance per mode to use both. When not set, "
            "the mode follows `CONNECTOR_TYPE`."
        ),
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ImportDocument connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_document: ImportDocumentConfig = Field(default_factory=ImportDocumentConfig)

    def to_helper_config(self) -> dict[str, Any]:
        """Convert the settings for pycti, with the connector type set by the mode.

        When `import_document.mode` is set, it takes precedence over
        `connector.type`. A catalog deployment cannot set `CONNECTOR_TYPE`, which
        the platform always injects from its own record of the connector.
        """
        helper_config = super().to_helper_config()
        if self.import_document.mode is not None:
            helper_config["connector"]["type"] = CONNECTOR_TYPE_BY_MODE[
                self.import_document.mode
            ]
        return helper_config
