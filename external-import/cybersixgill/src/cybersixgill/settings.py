"""OpenCTI Cybersixgill connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class CybersixgillConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4a843046-945d-4855-94ce-ead2bf5c8710",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Cybersixgill Darkfeed",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["cybersixgill"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )


class CybersixgillConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Cybersixgill` connector.
    """

    client_id: str = Field(
        description="Cybersixgill API Client ID.",
    )
    client_secret: SecretStr = Field(
        description="Cybersixgill API Client Secret.",
    )
    create_observables: bool = Field(
        description="Create observables from indicators.",
        default=True,
    )
    create_indicators: bool = Field(
        description="Create STIX indicators.",
        default=True,
    )
    enable_relationships: bool = Field(
        description="Create relationships between SDOs.",
        default=True,
    )
    fetch_size: int = Field(
        description="Number of indicators to fetch per run.",
        default=2000,
    )
    interval_sec: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda seconds: timedelta(seconds=int(seconds)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `CybersixgillConnectorConfig` and `CybersixgillConfig`.
    """

    connector: CybersixgillConnectorConfig = Field(
        default_factory=CybersixgillConnectorConfig
    )
    cybersixgill: CybersixgillConfig = Field(default_factory=CybersixgillConfig)
