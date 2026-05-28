from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
)
from pydantic import Field


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    """
    Override the `BaseInternalExportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_EXPORT_FILE`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="TemplateConnector",
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
