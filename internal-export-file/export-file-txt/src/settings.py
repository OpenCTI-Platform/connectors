"""Pydantic settings for the Export File TXT connector."""

from connectors_sdk import (
    BaseConnectorSettings,
    BaseInternalExportFileConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalExportFileConnectorConfig(BaseInternalExportFileConnectorConfig):
    """
    Override `BaseInternalExportFileConnectorConfig` to add connector-specific configuration
    parameters and/or defaults.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4ba9523e-5283-48ce-86e5-23f9c8223ac2",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ExportFileTxt",
    )
    scope: ListFromString = Field(
        default=["text/plain"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
