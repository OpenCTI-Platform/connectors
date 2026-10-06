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
        default="DomainToolsIrisDetectConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DomainToolsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DomainToolsIrisDetectConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")

    monitor_id: str | None = Field(
        description="Monitor ID from the monitors response – only used when requesting domains for specific monitors.",
        default=None,
    )
    store_iris_data: bool = Field(
        description="Store DomainTools Iris data as note object.", default=False
    )
    preview: bool = Field(
        description="Use during API implementation and testing. Including with value = 1 will limit results to 2 but not be limited by hourly restrictions.",
        default=False,
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


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `TemplateConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    domaintools: DomainToolsConfig = Field(default_factory=DomainToolsConfig)
