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
        default=timedelta(hours=1),
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
    interval: int = Field(description="Polling interval in hours.", default=3)
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
