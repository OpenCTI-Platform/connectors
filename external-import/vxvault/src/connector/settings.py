from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
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
    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(days=int(x)),
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
