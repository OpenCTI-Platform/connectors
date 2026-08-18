from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
)
from pydantic import Field


class ConnectorSettings(BaseConnectorSettings):
    connector: BaseInternalExportFileConnectorConfig = Field(
        default_factory=BaseInternalExportFileConnectorConfig
    )
