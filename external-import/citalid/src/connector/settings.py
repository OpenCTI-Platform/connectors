from datetime import timedelta
from typing import Optional

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
        default="bfbc4966-88dd-4d2a-9ded-4c97e4bf90b5",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Citalid",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CitalidConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CitalidConnector`.
    """

    customer_sub_domain_url: HttpUrl = Field(
        description="URL of your Citalid instance (customer subdomain).",
    )
    user: str = Field(
        description="Username with access to the Citalid instance.",
    )
    password: SecretStr = Field(
        description="Password for the Citalid user.",
    )
    interval: Optional[int] = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(hours=int(x)),
        description="Polling interval in hours between connector runs.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CitalidConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    citalid: CitalidConfig = Field(default_factory=CitalidConfig)
