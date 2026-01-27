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
        default="AA0852B9-D7BE-4C09-A4A8-B1FC202A6851",
    )
    name: str = Field(
        description="The name of the connector.",
        default="MITRE ATLAS",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "identity",
            "attack - pattern",
            "course - of - action",
            "relationship",
            "x - mitre - collection",
            "x - mitre - matrix",
            "x - mitre - tactic",
        ],
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
