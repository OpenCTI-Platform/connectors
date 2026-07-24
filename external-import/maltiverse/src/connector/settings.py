from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6c54218c-0098-4446-86a8-a6da32949c1e",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Maltiverse",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MaltiverseConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MaltiverseConnector`.
    """

    user: str = Field(description="Maltiverse account username/email.")
    passwd: SecretStr = Field(description="Maltiverse account password.")
    feeds: str = Field(
        description="Comma-separated list of feed/collection IDs to fetch."
    )
    poll_interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(hours=int(x)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MaltiverseConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    maltiverse: MaltiverseConfig = Field(default_factory=MaltiverseConfig)
