from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator

SCOPE_ENTITIES = [
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "stixfile",
    "vulnerability",
]
VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS = ["aiInsights", "cpe", "risk"]


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
        default="RecordedFutureEnrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=SCOPE_ENTITIES,
    )

    @field_validator("scope", mode="after")
    @classmethod
    def validate_scope_entities(cls, scope: list[str]) -> list[str]:
        if invalids := [entity for entity in scope if entity not in SCOPE_ENTITIES]:
            raise ValueError(
                f"Invalid scope: {', '.join(invalids)} are not in {', '.join(SCOPE_ENTITIES)}"
            )
        return scope


class RecordedfutureEnrichmentConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RecordedfutureEnrichmentConnector`.
    """

    token: SecretStr = Field(
        description="API Token for Recorded Future.",
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
    threat_actor_to_intrusion_set: bool = Field(
        default=False,
        description="Whether to convert Threat Actor entities to Intrusion Set entities.",
    )
    vulnerability_enrichment_optional_fields: ListFromString = Field(
        description="A list of optional fields to enrich vulnerabilities with. (For vulnerability enrichment only)",
        default=[],
    )

    @field_validator("vulnerability_enrichment_optional_fields", mode="after")
    @classmethod
    def validate_vulnerability_enrichment_optional_fields(
        cls, vulnerability_enrichment_optional_fields: list[str]
    ) -> list[str]:
        if invalids := [
            field
            for field in vulnerability_enrichment_optional_fields
            if field not in VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS
        ]:
            raise ValueError(
                f"Invalid vulnerability enrichment optional field(s): {', '.join(invalids)} are not in {', '.join(VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS)}"
            )
        return vulnerability_enrichment_optional_fields


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
