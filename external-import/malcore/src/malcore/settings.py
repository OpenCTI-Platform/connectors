from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="158ee4df-f9b5-47ea-955f-d2b83e8e5659",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Malcore",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MalcoreConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MalcoreConnector`.
    """

    api_url: str = Field(
        description="Malcore API URL",
        default="https://api.malcore.io/api/feed",
    )
    api_key: SecretStr = Field(
        description="Malcore API Key",
    )
    score: int = Field(
        description="Parameter not used at this moment, but could be used as a default indicator/observable score at a later date",
        default=100,
        deprecated=True,
    )
    limit: int = Field(
        description="Parameter not used at this moment, but could be used as a limit on the number of entities to be retrieved per request at a later date",
        default=10000,
        deprecated=True,
    )
    interval: int = Field(
        description="Interval between two executions, in hours (must be > 1)",
        default=12,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MalcoreConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    malcore: MalcoreConfig = Field(default_factory=MalcoreConfig)
