"""OpenCTI Orange Cyberdefense Enrichment connector settings module."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr


class OrangeCyberdefenseEnrichmentConnectorConfig(
    BaseInternalEnrichmentConnectorConfig
):
    """Defaults of the `connector` section for the Orange Cyberdefense Enrichment connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="cb4ab06c-1514-4e80-8b35-46cbf914781b",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Orange Cyberdefense CTI Enrichment",
    )
    scope: ListFromString = Field(
        description="OpenCTI observable types for which to enable the enrichment.",
        default=[
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "URL",
            "Email-Addr",
            "Autonomous-System",
            "X509-Certificate",
            "Cryptocurrency-Wallet",
            "StixFile",
            "Phone-Number",
        ],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    max_tlp: TLPLevel = Field(
        description=(
            "Only perform enrichment for observables with this TLP level or less restrictive."
        ),
        default=TLPLevel.GREEN,
    )


class OrangeCyberdefenseEnrichmentConfig(BaseConfigModel):
    """Settings specific to the Orange Cyberdefense Enrichment connector."""

    datalake_token: SecretStr = Field(
        description="Long Term Token used to access Orange Cyberdefense Datalake API.",
    )
    datalake_env: Literal["prod", "preprod"] = Field(
        description="Datalake environment to use: `prod` or `preprod`.",
        default="prod",
    )
    ignore_unscored_indicators: bool = Field(
        description="If `true`, Datalake indicators that do not have any score will be ignored.",
        default=True,
    )
    ignore_whitelisted_indicators: bool = Field(
        description="If `true`, Datalake indicators that are whitelisted will be ignored.",
        default=True,
    )
    fallback_score: int = Field(
        description=(
            "If `OCD_ENRICH_IGNORE_UNSCORED_INDICATORS` is set to `false`, this value will "
            "be used as a default for Datalake indicators without any score."
        ),
        default=0,
        ge=0,
        le=100,
    )
    add_tags_as_labels: bool = Field(
        description="Whether to add Datalake tags as labels to the enriched observable.",
        default=True,
    )
    add_scores_as_labels: bool = Field(
        description="Whether to add Datalake threat scores as labels to the enriched observable.",
        default=True,
    )
    add_tlp: bool = Field(
        description="Whether to add a TLP marking to the enriched observable (overwrite existing).",
        default=True,
    )
    threat_actor_as_intrusion_set: bool = Field(
        description=(
            "Whether to transform Datalake 'Threat Actor' objects into 'Intrusion Set' objects."
        ),
        default=True,
    )
    add_score: bool = Field(
        description="Whether to add score to the enriched observable (overwrite existing).",
        default=True,
    )
    add_extref: bool = Field(
        description="Whether to add external references to the enriched observable.",
        default=True,
    )
    add_summary: bool = Field(
        description="Whether to add a threat summary as a note to the enriched observable.",
        default=True,
    )
    add_related: bool = Field(
        description=(
            "Whether to import objects from the Threat Library related to this observable, "
            "such as indicators, malwares, etc."
        ),
        default=True,
    )
    add_sightings: bool = Field(
        description="Whether to import positive sightings from Datalake.",
        default=True,
    )
    add_createdby: bool = Field(
        description=(
            "Whether to add a reference to 'Orange Cyberdefense' organization as author "
            "of OpenCTI objects."
        ),
        default=True,
    )
    curate_labels: bool = Field(
        description="Adapt Datalake CTI tags as STIX labels.",
        default=True,
    )
    max_tlp: str | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_MAX_TLP' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="max_tlp",
        description=(
            "Only perform enrichment for observables with this TLP level or less restrictive."
        ),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Orange Cyberdefense Enrichment connector."""

    connector: OrangeCyberdefenseEnrichmentConnectorConfig = Field(
        default_factory=OrangeCyberdefenseEnrichmentConnectorConfig
    )
    ocd_enrich: OrangeCyberdefenseEnrichmentConfig = Field(
        default_factory=OrangeCyberdefenseEnrichmentConfig
    )
