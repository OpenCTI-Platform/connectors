from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="2b8cdcb6-ae91-4f2c-ae1f-b0eb52b57f40",
    )
    name: str = Field(
        description="The name of the connector.",
        default="MitreAtlas",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MitreAtlasConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MitreAtlasConnector`.
    """

    url: str = Field(
        description="The URL of the MITRE ATLAS file to import.",
        default="https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json",
    )
    interval: int = Field(
        description="The interval in days between two imports of the MITRE ATLAS file.",
        default=7,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MitreAtlasConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    mitre_atlas: MitreAtlasConfig = Field(default_factory=MitreAtlasConfig)
