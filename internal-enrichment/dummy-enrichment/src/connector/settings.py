from datetime import date
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
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
    mamama: SkipValidation[int] = DeprecatedField(
        new_namespaced_var="momomo",
        removal_date=date(2026, 6, 1),
    )
    momomo: str = Field(description="momomo")
    interval: SkipValidation[int] = DeprecatedField(
        deprecated="Use connector.duration_period instead",
        new_namespaced_var="duration_period",
        new_namespace="connector",
        new_value_factory=lambda x: int(x) * 60,
        removal_date=date(2026, 3, 1),
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
    tata: SkipValidation[TotoConfig] = DeprecatedField(
        deprecated="Use toto",
        new_namespace="toto",
        removal_date=date(2026, 4, 1),
    )
    dummy_enrichment: SkipValidation[DummyConfig] = DeprecatedField(
        deprecated="Use dummy_enrichment_new",
        new_namespace="dummy_enrichment_new",
        removal_date=date(2026, 5, 1),
    )
    dummy_enrichment_new: DummyConfig = Field(default_factory=DummyConfig)
    christmas: ChristmasConfig = Field(default_factory=ChristmasConfig)
    christmas_old: SkipValidation[ChristmasConfig] = DeprecatedField(
        deprecated="Use christmas",
        new_namespace="christmas",
        removal_date="2026-12-25",
    )
