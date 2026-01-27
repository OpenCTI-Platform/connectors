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
        default="971377CA-CA0E-41C2-BC96-8B8CCD8216BE",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Red Flag Domains",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["red-flag-domains"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class RedFlagDomainsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RedFlagDomainsConnector`.
    """

    url: str = Field(
        description="The Red Flag Domains URL.",
        default="https://dl.red.flag.domains/daily/",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RedFlagDomainsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    red_flag_domains: RedFlagDomainsConfig = Field(default_factory=RedFlagDomainsConfig)
