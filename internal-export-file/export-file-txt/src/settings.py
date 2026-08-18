"""Pydantic settings for the Export File TXT connector."""

from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
)
from pydantic import Field


class ConnectorSettings(BaseConnectorSettings):
    """Configuration of the Export File TXT connector."""

    connector: BaseInternalExportFileConnectorConfig = Field(
        default_factory=BaseInternalExportFileConnectorConfig,
        description="Connector configurations.",
    )
