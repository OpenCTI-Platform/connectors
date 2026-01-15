from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="IBMXTIConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )


class IBMXTIConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `IBMXTIConnector`.
    """

    taxii_server_url: HttpUrl = Field(
        description="The base URL of the IBM X-Force PTI TAXII Server."
    )
    taxii_user: str = Field(description="Your TAXII Server username.")
    taxii_pass: str = Field(description="Your TAXII Server password.")
    taxii_collections: str = Field(
        description="Comma-separated list of collection IDs to ingest.", default=""
    )

    create_observables: bool = Field(
        description="Create observables from indicators.", default=False
    )

    debug: bool = Field(
        description="Enable debug mode (developers only)", default=False
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `IBMXTIConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig  # type: ignore
    )
    ibm_xti: IBMXTIConfig = Field(default_factory=IBMXTIConfig)  # type: ignore
