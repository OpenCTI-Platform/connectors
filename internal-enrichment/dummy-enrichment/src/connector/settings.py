from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedNameSpace,
    DeprecatedVariable,
    LegacyField,
)
from pydantic import Field, HttpUrl


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="DummyEnrichmentConnector",
    )
    duration_period: int = Field(
        description="The period (in seconds) between two runs of the connector.",
    )


class DummyConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DummyEnrichmentConnector`.
    """

    api_base_url: HttpUrl = Field(description="External API base URL.")
    api_key: str = Field(description="API key for authentication.")
    max_tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Max TLP level of the entities to enrich.",
        default="amber+strict",
    )
    table: str = Field(description="Table")


class TotoConfig(BaseConfigModel):
    image: str = Field(description="image")
    movie: str = Field(description="movie")
    useless: DeprecatedVariable
    mamama: DeprecatedVariable = LegacyField(new_variable_name="momomo")
    momomo: str = Field(description="momomo")
    interval: DeprecatedVariable = LegacyField(
        deprecated="Use connector.duration_period instead",
        new_variable_name="duration_period",
        new_namespace="connector",
        change_value=lambda x: int(x) * 60,
    )


class ChristmasConfig(BaseConfigModel):
    os: str = Field(description="os")
    day: str = Field(description="day")


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DummyEnrichmentConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )

    toto: TotoConfig = Field(default_factory=TotoConfig)
    tata: DeprecatedNameSpace = LegacyField(
        deprecated="Use toto",
        new_namespace="toto",
    )
    dummy_enrichment: DeprecatedNameSpace = LegacyField(
        deprecated="Use dummy_enrichment_new",
        new_namespace="dummy_enrichment_new",
    )
    dummy_enrichment_new: DummyConfig = Field(default_factory=DummyConfig)
    christmas: ChristmasConfig = Field(default_factory=ChristmasConfig)
    christmas_old: DeprecatedNameSpace = LegacyField(
        deprecated="Use christmas", new_namespace="christmas"
    )
