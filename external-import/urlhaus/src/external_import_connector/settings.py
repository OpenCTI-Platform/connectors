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
        default="e6b8818b-04f2-4781-81e0-fb2652799ab6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Urlhaus",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=3),
    )


class UrlhausConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `UrlhausConnector`.
    """

    csv_url: str = Field(
        description="URLhaus CSV feed URL.",
        default="https://urlhaus.abuse.ch/downloads/csv_recent/",
    )
    default_x_opencti_score: int = Field(
        description="Default x_opencti_score for imported indicators.", default=80
    )
    import_offline: bool = Field(
        description="Import URLs marked as 'offline' in addition to 'online'.",
        default=True,
    )
    interval: int = Field(
        description="Polling interval in hours.",
        default=3,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
    )
    threats_from_labels: bool = Field(
        description="Create relationships to existing threats based on URL tags.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `UrlhausConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    urlhaus: UrlhausConfig = Field(default_factory=UrlhausConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `URLHAUS_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        urlhaus_data: dict = data.get("urlhaus", {})
        if interval := urlhaus_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'URLHAUS_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'URLHAUS_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(hours=int(interval))

        return data
