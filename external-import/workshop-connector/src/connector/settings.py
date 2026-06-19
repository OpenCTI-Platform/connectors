from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="WorkshopConnectorConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class WorkshopConnectorConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `WorkshopConnectorConnector`.
    """

    sample_file_path: str = Field(description="File path to samples.")
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `WorkshopConnectorConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    workshop_connector: WorkshopConnectorConfig = Field(
        default_factory=WorkshopConnectorConfig
    )
