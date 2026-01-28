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
        default="15485709-5df3-41ef-aaa9-6a4277d0a3e4",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Wiz Cloud Threat Landscape",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class WizConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `WizConnector`.
    """

    threat_actor_as_intrusion_set: bool = Field(
        description="Convert Threat Actor objects to Intrusion Set objects.",
        default=False,
    )
    tlp_level: str = Field(
        description="TLP marking: `white`, `green`, `amber`, `amber+strict`, `red`.",
        default="clear",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `WizConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    wiz: WizConfig = Field(default_factory=WizConfig)
