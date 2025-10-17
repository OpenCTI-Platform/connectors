from pydantic import Field, HttpUrl
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)


class ExternalImportConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Template Connector",
    )


class TemplateConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TemplateConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")
    tlp_level: str = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConfig` and `TemplateConfig`.
    """

    connector: ExternalImportConfig = Field(default_factory=ExternalImportConfig)
    template: TemplateConfig = Field(default_factory=TemplateConfig)
