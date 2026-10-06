"""OpenCTI Cybersixgill connector settings module."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr
from pydantic.json_schema import SkipJsonSchema


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
    update_existing_data: bool = Field(
        description="Whether to update data already ingested into the platform.",
        default=False,
    )
    # Override `BaseExternalImportConnectorConfig.duration_period` as the connector
    # keeps its own scheduling loop, driven by `cybersixgill.interval_sec`.
    duration_period: SkipJsonSchema[None] = Field(
        description="Do not use. Not implemented in the connector yet, use `CYBERSIXGILL_INTERVAL_SEC` instead.",
        default=None,
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
    interval_sec: int = Field(
        description="Import interval in seconds.",
        default=300,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `CybersixgillConnectorConfig` and `CybersixgillConfig`.
    """

    connector: CybersixgillConnectorConfig = Field(
        default_factory=CybersixgillConnectorConfig
    )
    cybersixgill: CybersixgillConfig = Field(default_factory=CybersixgillConfig)
