from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    LegacyField,
)
from connectors_sdk.settings.annotated_types import ListFromString
from pydantic import Field, HttpUrl, SkipValidation


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
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["dummy"],
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
    mamama: SkipValidation[int] = LegacyField(
        new_variable_name="momomo",
        removal_date="2026-06-01",
    )
    momomo: str = Field(description="momomo")
    interval: SkipValidation[int] = LegacyField(
        deprecated="Use connector.duration_period instead",
        new_variable_name="duration_period",
        new_namespace="connector",
        change_value=lambda x: int(x) * 60,
        removal_date="2026-03-01",
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
    tata: SkipValidation[TotoConfig] = LegacyField(
        deprecated="Use toto",
        new_namespace="toto",
        removal_date="2026-04-01",
    )
    dummy_enrichment: SkipValidation[DummyConfig] = LegacyField(
        deprecated="Use dummy_enrichment_new",
        new_namespace="dummy_enrichment_new",
        removal_date="2026-05-01",
    )
    dummy_enrichment_new: DummyConfig = Field(default_factory=DummyConfig)
    christmas: ChristmasConfig = Field(default_factory=ChristmasConfig)
    christmas_old: SkipValidation[ChristmasConfig] = LegacyField(
        deprecated="Use christmas",
        new_namespace="christmas",
        removal_date="2026-12-25",
    )
