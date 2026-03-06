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
        default="40e82dac-3cfb-4c86-bb56-a5e9ba05a261",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Opencti",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class OpenctiConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `OpenctiConnector`.
    """

    sectors_file_url: str = Field(
        description="URL to sectors dataset (set to `false` to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json",
    )
    geography_file_url: str = Field(
        description="URL to geography dataset (set to `false` to disable).",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json",
    )
    companies_file_url: str = Field(
        description="URL to companies dataset.",
        default="https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json",
    )
    remove_creator: bool = Field(
        description="Remove creator identity from imported objects.",
        default=False,
    )
    interval: int = Field(
        description="Interval in days between connector runs.",
        default=7,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `OpenctiConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    config: OpenctiConfig = Field(default_factory=OpenctiConfig)
