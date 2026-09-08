from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CYFIRMA",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CyfirmaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to `CyfirmaConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")
    tailored_iocs: bool = Field(
        description="Whether to fetch tailored IOCs.",
        default=True,
    )
    look_back_days: int = Field(
        description="Number of days to look back for fetching IOCs.",
        default=7,
        ge=1,
        le=7,
    )
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
    tailored_vulnerabilities: bool = Field(
        description="Whether to fetch tailored vulnerabilities.",
        default=False,
    )



class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CyfirmaConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    cyfirma: CyfirmaConfig = Field(default_factory=CyfirmaConfig)

