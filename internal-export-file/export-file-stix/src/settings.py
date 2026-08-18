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

    scope: ListFromString = Field(
        default=["application/vnd.oasis.stix+json"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: InternalExportFileConnectorConfig = Field(
        default_factory=InternalExportFileConnectorConfig
    )
