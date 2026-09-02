"""Pydantic settings for the Export TTPs File Navigator connector."""

from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    """
    Override the `BaseConnectorConfig` to add connector specific configuration parameters and/or defaults.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="0bc22724-1cd0-416c-b400-6d4e9fbf9829",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ExportTTPsFileNavigator",
    )
    scope: ListFromString = Field(
        default=["application/vnd.mitre.navigator+json"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
