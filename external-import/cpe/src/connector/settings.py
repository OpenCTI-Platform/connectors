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
        default="44bc8c82-bb5f-4cd1-85a4-6f1d4c89e8b6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Cpe",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CpeConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CpeConnector`.
    """

    base_url: str = Field(
        description="URL for the NIST NVD CPE API.",
        default="https://services.nvd.nist.gov/rest/json/cpes/2.0",
    )
    api_key: SecretStr = Field(
        description="API Key for the NIST NVD API.",
        default=SecretStr("ChangeMe"),
    )
    interval: str = Field(
        description="Interval between collections (format: `6h` for hours, `3600s` for seconds). Minimum recommended: 6 hours.",
        default="6h",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CpeConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    cpe: CpeConfig = Field(default_factory=CpeConfig)
