from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override BaseInternalImportFileConnectorConfig to add defaults for ImportFileStix."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="f2637f59-2103-4e1b-b250-7825e3033122",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ImportFileStix",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["application/json", "text/xml"],
    )
    validate_before_import: bool = Field(
        description="Validate any bundle before import.",
        default=True,
    )


class ImportFileStixConfig(BaseConfigModel):
    """Config fields specific to the ImportFileStix connector.

    This connector has no custom configuration fields beyond the standard connector settings.
    """

    pass


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ImportFileStix connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_file_stix: ImportFileStixConfig = Field(default_factory=ImportFileStixConfig)
