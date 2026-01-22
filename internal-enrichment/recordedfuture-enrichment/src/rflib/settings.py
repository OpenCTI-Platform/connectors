from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="2f27b156-6185-4d5f-86b8-5739f3ef39a9",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RecordedfutureEnrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class RecordedfutureEnrichmentConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RecordedfutureEnrichmentConnector`.
    """

    token: SecretStr = Field(
        description="API Token for Recorded Future.",
        default=SecretStr("ChangeMe"),
    )
    create_indicator_threshold: int = Field(
        description="The risk score threshold at which an indicator will be created for enriched observables.",
        ge=0,
        le=100,
        default=0,
    )
    info_max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Max TLP marking of the entity to enrich (inclusive).",
        default="TLP:AMBER",
    )
    vulnerability_enrichment_optional_fields: str = Field(
        description="A list of optional fields to enrich vulnerabilities with. (For vulnerability enrichment only)",
        default="aiInsights,cpe,risk",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `RecordedfutureEnrichmentConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    recorded_future: RecordedfutureEnrichmentConfig = Field(
        default_factory=RecordedfutureEnrichmentConfig
    )
