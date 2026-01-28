import warnings
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, model_validator


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
        default=timedelta(days=7),
    )


class MitreAtlasConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MitreAtlasConnector`.
    """

    url: str = Field(
        description="The URL of the MITRE ATLAS file to import.",
        default="https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json",
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `MITRE_ATLAS_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        mitre_atlas_data: dict = data.get("mitre_atlas", {})
        if interval := mitre_atlas_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'MITRE_ATLAS_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'MITRE_ATLAS_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(days=int(interval))

        return data


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MitreAtlasConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    mitre_atlas: MitreAtlasConfig = Field(default_factory=MitreAtlasConfig)
