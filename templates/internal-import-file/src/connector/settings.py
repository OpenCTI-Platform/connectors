from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalImportFileConnectorConfig,
)
from pydantic import Field


class InternalImportFileConnectorConfig(BaseInternalImportFileConnectorConfig):
    """
    Override the `BaseInternalImportFileConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_IMPORT_FILE`.
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
    Override `BaseConnectorSettings` to include `InternalImportFileConnectorConfig` and `TemplateConfig`.
    """

    connector: InternalImportFileConnectorConfig = Field(
        default_factory=InternalImportFileConnectorConfig
    )
    template: TemplateConfig = Field(default_factory=TemplateConfig)
