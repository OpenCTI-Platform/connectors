from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="b36f3005-427d-443b-bb34-e8534d0cf8a0",
    )
    name: str = Field(
        description="The name of the connector.",
        default="DomainToolsIrisQLConnector",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["stix2"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DomainToolsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DomainToolsIrisQLConnector`.
    """

    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: SecretStr = Field(description="API key for authentication.")
    iris_ql: str = Field(description="The query search string.")
    store_iris_data: bool | None = Field(
        description="Store DomainTools Iris data as note object.", default=False
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
