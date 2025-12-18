from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.utils.deprecations import (
    migrate_deprecated_namespace,
    rename_deprecated_variable,
)
from pydantic import Field, HttpUrl, model_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="DummyEnrichmentConnector",
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


class ChristmasConfig(BaseConfigModel):
    os: str = Field(description="os")
    day: str = Field(description="day")


class BrouetteConfig(BaseConfigModel):
    number: int = Field(description="number")
    black: str = Field(description="black")


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DummyEnrichmentConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )

    toto: TotoConfig = Field(default_factory=TotoConfig)
    tata: dict = Field(default=None, deprecated="Use toto")
    dummy_enrichment: dict = Field(
        default_factory=dict, deprecated="Use dummy_enrichment_new"
    )
    dummy_enrichment_new: DummyConfig = Field(default_factory=DummyConfig)
    christmas: ChristmasConfig = Field(default_factory=ChristmasConfig)
    christmas_old: dict = Field(default_factory=dict, deprecated="Use christmas")
    new_brouette: BrouetteConfig = Field(default_factory=BrouetteConfig)
    brouette: dict = Field(default_factory=dict, deprecated="Use new_brouette")

    @model_validator(mode="before")
    @classmethod
    @migrate_deprecated_namespace(old="dummy_enrichment", new="dummy_enrichment_new")
    @migrate_deprecated_namespace(old="tata", new="toto")
    @migrate_deprecated_namespace(old="christmas_old", new="christmas")
    @migrate_deprecated_namespace(old="brouette", new="new_brouette")
    @rename_deprecated_variable(namespace="new_brouette", old="color", new="black")
    def merge_legacy(cls, data):
        return data
