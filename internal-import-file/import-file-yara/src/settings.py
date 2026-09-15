from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override BaseInternalImportFileConnectorConfig with ImportFileYARA defaults.

    Mirrors the connector's existing ``connector`` section variables one-to-one,
    including the legacy ``validate_before_import``fields
    the connector still relies on.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ImportFileYARA",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4a29c1e2-3d76-4967-8111-fd1836eacbb5",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["text/yara+plain"],
    )
    validate_before_import: bool = Field(
        description="Validate any bundle before import.",
        default=True,
    )


class YaraImportFileConfig(BaseConfigModel):
    """Config fields specific to the ImportFileYARA connector.

    Mirrors the connector's existing ``yara_import_file`` section variables one-to-one.
    """

    split_rules: bool = Field(
        description="Whether to create one indicator per YARA rule instead of a single indicator per file.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ImportFileYARA connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    yara_import_file: YaraImportFileConfig = Field(default_factory=YaraImportFileConfig)
