from pydantic import BaseModel, Field, HttpUrl
from shared.opencti_connector_settings.src.connector_base_settings import (
    OpenCTIConnectorSettings,
)


class _ConfigConnectorTemplate(BaseModel):
    api_base_url: HttpUrl = Field(description="API base URL for the connector")
    api_key: str = Field(description="API key for the connector")
    tlp_level: str = Field(description="TLP level for the connector")


class ConfigConnector(OpenCTIConnectorSettings):
    connectortemplate: _ConfigConnectorTemplate
