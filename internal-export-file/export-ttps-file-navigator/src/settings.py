"""Pydantic settings for the Export TTPs File Navigator connector."""

from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
)
from pydantic import Field


class ConnectorSettings(BaseConnectorSettings):
    """Settings for the Export TTPs File Navigator connector.

    This connector has no connector-specific configuration variables: it only
    relies on the standard `opencti` and `connector` configuration sections.
    """

    connector: BaseInternalExportFileConnectorConfig = Field(
        default_factory=BaseInternalExportFileConnectorConfig,  # type: ignore[arg-type]
        description="Connector configurations.",
    )
