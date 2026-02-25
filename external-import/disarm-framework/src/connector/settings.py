import warnings
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, model_validator


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
        description="The scope of the connector. Only these object types will be imported on OpenCTI.",
        default=[
            "marking-definition",
            "identity",
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "report",
            "narrative",
            "event",
            "channel",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=7),
    )


class DisarmFrameworkConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DisarmFrameworkConnector`.
    """

    url: HttpUrl = Field(
        description="URL of the DISARM STIX bundle.",
        default=HttpUrl(
            "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_files/DISARM_STIX/DISARM.json"
        ),
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

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `DISARM_FRAMEWORK_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        disarm_framework_data: dict = data.get("disarm_framework", {})
        if interval := disarm_framework_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'DISARM_FRAMEWORK_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'DISARM_FRAMEWORK_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(days=int(interval))

        return data
