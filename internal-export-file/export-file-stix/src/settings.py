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
        default="9c06c7a0-96e3-4ca5-924c-5437587660f1",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ExportFileStix2",
    )
    scope: ListFromString = Field(
        default=["application/vnd.oasis.stix+json"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
