from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="73d5e2a2-fb78-417c-839e-729d6d0d220a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DisarmFramework",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DisarmFrameworkConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DisarmFrameworkConnector`.
    """

    url: str = Field(
        description="URL of the DISARM STIX bundle.",
        default="https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_files/DISARM_STIX/DISARM.json",
    )
    interval: int = Field(
        description="Polling interval in days.",
        default=7,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `DisarmFrameworkConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    disarm_framework: DisarmFrameworkConfig = Field(
        default_factory=DisarmFrameworkConfig
    )
