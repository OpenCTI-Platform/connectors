from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Silobreaker",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class SilobreakerConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SilobreakerConnector`.
    """

    api_url: str = Field(
        description="The URL of the Silobreaker API.",
        default="https://api.silobreaker.com",
    )
    api_key: SecretStr = Field(
        description="The API key for the Silobreaker API.",
    )
    api_shared: SecretStr = Field(
        description="The shared secret for the Silobreaker API.",
    )
    lists: str = Field(
        description="The lists of Silobreaker to import.",
        default="138809,96910,36592,55112,50774",
    )
    import_start_date: str = Field(
        description="The start date for importing Silobreaker data.",
        default="2024-09-01",
    )
    interval: int = Field(
        description="The interval in minutes for importing Silobreaker data.",
        default=60,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SilobreakerConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    silobreaker: SilobreakerConfig = Field(default_factory=SilobreakerConfig)
