from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """Override BaseInternalImportFileConnectorConfig with ImportTTPsFileNavigator defaults.

    Mirrors the connector's existing ``connector`` section variables one-to-one.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ImportTTPsFileNavigator",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="cd378276-d36c-4cfd-99ab-20241e4b6bb3",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["application/json"],
    )


class ImportTTPsFileNavigatorConfig(BaseConfigModel):
    """Config fields specific to the ImportTTPsFileNavigator connector.

    This connector has no custom configuration fields beyond the standard
    connector settings.
    """


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ImportTTPsFileNavigator connector."""

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    import_ttps_file_navigator: ImportTTPsFileNavigatorConfig = Field(
        default_factory=ImportTTPsFileNavigatorConfig
    )
