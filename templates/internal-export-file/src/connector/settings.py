from pydantic import Field
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
)


class InternalExportFileConfig(BaseInternalExportFileConnectorConfig):
    """
    Override the `BaseInternalExportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_EXPORT_FILE`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Template Connector",
    )


class TemplateConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TemplateConnector`.
    """

    api_key: str = Field(description="API key for authentication.")


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalExportFileConfig` and `TemplateConfig`.
    """

    connector: InternalExportFileConfig = Field(
        default_factory=InternalExportFileConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
