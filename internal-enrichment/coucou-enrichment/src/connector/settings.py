from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Coucou Enrichment",
    )
    scope: ListFromString = Field(
        description="The entity types the connector enriches.",
        default=["IPv4-Addr"],
    )


class CoucouEnrichmentConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CoucouEnrichmentConnector`.
    """

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


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `CoucouEnrichmentConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    coucou_enrichment: CoucouEnrichmentConfig = Field(
        default_factory=CoucouEnrichmentConfig
    )
