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
        default="d790f4c0-84c1-4e91-8e6b-3a6f3a0e3b7a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="VX Vault URL list",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["vxvault"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=3),
    )


class VxvaultConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the VXVault connector.
    """

    url: str = Field(
        description="The URL of the VXVault dataset to fetch.",
        default="https://vxvault.net/URL_List.php",
    )
    create_indicators: bool = Field(
        description="If true, create indicators from the imported URLs.",
        default=True,
    )
    interval: int = Field(
        description="Polling interval in days.",
        default=3,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates when fetching the dataset.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `VxvaultConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    vxvault: VxvaultConfig = Field(default_factory=VxvaultConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `VXVAULT_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        vxvault_data: dict = data.get("vxvault", {})
        if interval := vxvault_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'VXVAULT_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'VXVAULT_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(days=int(interval))

        return data
