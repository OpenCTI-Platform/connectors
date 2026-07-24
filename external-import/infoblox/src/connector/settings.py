from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
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
        default="8f2a1b3c-4d5e-4f6a-8b9c-0d1e2f3a4b5c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Infoblox",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["infoblox"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=12),
    )


class InfobloxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Infoblox connector.
    """

    api_key: SecretStr = Field(
        description="The API key used to authenticate against the Infoblox TIDE API.",
    )
    url: HttpUrl = Field(
        description="The Infoblox TIDE API endpoint to fetch threat data from.",
        default=HttpUrl("https://csp.infoblox.com/tide/api/data/threats"),
    )
    ioc_limit: str = Field(
        description="Limit of IOCs to import (for each IOC type).",
        default="10000",
    )
    marking_definition: str = Field(
        description="The marking definition to apply to imported data (e.g. 'TLP:AMBER+STRICT').",
        default="TLP:AMBER+STRICT",
    )
    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(hours=int(x)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `InfobloxConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    infoblox: InfobloxConfig = Field(default_factory=InfobloxConfig)
