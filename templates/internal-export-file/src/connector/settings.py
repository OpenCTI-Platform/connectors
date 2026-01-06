from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    """
    Override the `BaseInternalExportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_EXPORT_FILE`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="00000000-0000-0000-0000-000000000000",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TemplateConnector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class TemplateConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TemplateConnector`.
    """

    api_key: str = Field(description="API key for authentication.")


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalExportFileConnectorConfig` and `TemplateConfig`.
    """

    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
