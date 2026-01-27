import warnings
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="2A52C9F0-2E35-4ED4-A628-FF18E9631985",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Common Platform Enumeration",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["software"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=6),
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
    )

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `CPE_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        cpe_data: dict = data.get("cpe", {})
        if interval := cpe_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'CPE_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'CPE_INTERVAL' is deprecated. "
                    "Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(hours=int(interval))

        return data


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CpeConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    cpe: CpeConfig = Field(default_factory=CpeConfig)
