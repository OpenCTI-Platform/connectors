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
        default="16146fa8-f9dd-4fe8-9061-18787424fcb6",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RedFlagDomains",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
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
