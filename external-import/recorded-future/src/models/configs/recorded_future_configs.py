from typing import Literal, Optional

from connectors_sdk.core.pydantic import ListFromString
from models.configs.base_settings import ConfigBaseSettings
from pydantic import Field, PositiveInt, SecretStr, field_validator


class _ConfigLoaderRecordedFuture(ConfigBaseSettings):
    """Interface for loading Recorded Future dedicated configuration."""

    # Core RF configuration
    token: SecretStr = Field(
        description="Recorded Future API token for authentication.",
    )
    initial_lookback: PositiveInt = Field(
        default=240,
        description="Initial lookback period in hours when first running the connector.",
    )
    tlp: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = Field(
        default="amber+strict",
        description="Default Traffic Light Protocol (TLP) marking for imported data.",
    )

    @field_validator("tlp", mode="before")
    @classmethod
    def validate_tlp_lowercase(cls, v: str) -> str:
        """Convert TLP value to lowercase."""
        return v.lower()

    interval: PositiveInt = Field(
        default=1,
        description="Polling interval in hours for fetching Recorded Future data.",
    )

    # Analyst Notes configuration
    pull_analyst_notes: bool = Field(
        default=True,
        description="Whether to import Recorded Future analyst notes.",
    )
    last_published_notes: PositiveInt = Field(
        default=24,
        description="Time window in hours for fetching recently published analyst notes.",
    )
    topic: Optional[ListFromString] = Field(
        default=["VTrvnW", "g1KBGI", "ZjnoP0", "aDKkpk", "TXSFt5", "UrMRnT", "TXSFt3"],
        description=(
            "Comma-separated list of topic IDs to filter analyst notes. "
            "Examples: VTrvnW (Yara Rule), g1KBGI (Sigma Rule), ZjnoP0 (Snort Rule), "
            "aDKkpk (TTP Instance), TXSFt5 (Validated Intelligence Event), "
            "UrMRnT (Informational), TXSFt3 (Threat Lead)."
        ),
    )
    insikt_only: bool = Field(
        default=True,
        description="Whether to import only Insikt notes (Recorded Future's analyst reports).",
    )
    pull_signatures: bool = Field(
        default=False,
        description="Whether to import detection signatures (Yara/Snort/Sigma rules) from analyst notes.",
    )
    person_to_ta: bool = Field(
        default=False,
        alias="person_to_TA",
        description="Whether to convert Person entities to Threat Actor entities.",
    )
    ta_to_intrusion_set: bool = Field(
        default=False,
        alias="TA_to_intrusion_set",
        description="Whether to convert Threat Actor entities to Intrusion Set entities.",
    )
    risk_as_score: bool = Field(
        default=True,
        description="Whether to import risk scores as confidence scores in OpenCTI.",
    )
    risk_threshold: Optional[PositiveInt] = Field(
        default=60,
        description="Minimum risk score threshold (0-100) for importing entities.",
    )
    analyst_notes_guess_relationships: bool = Field(
        default=False,
        description="Enable or disable the automatic guessing of relationships between entities when processing analyst notes.",
    )

    # Risk List configuration
    pull_risk_list: bool = Field(
        default=False,
        description="Whether to import Recorded Future risk lists.",
    )
    riskrules_as_label: bool = Field(
        default=False,
        description="Whether to import risk rules as labels in OpenCTI.",
    )
    risk_list_threshold: Optional[PositiveInt] = Field(
        default=70,
        description="Minimum risk score threshold (0-100) for importing risk list entities.",
    )
    risklist_related_entities: Optional[ListFromString] = Field(
        default=["Malware", "Hash", "URL", "Threat Actor", "MitreAttackIdentifier"],
        description=(
            "Comma-separated list of entity types to import from risk lists. "
            "Available choices: Malware, Hash, URL, Threat Actor, MitreAttackIdentifier."
        ),
    )

    # Threat Maps configuration
    pull_threat_maps: bool = Field(
        default=False,
        description="Whether to import Threat Actors and Malware from Recorded Future threat maps.",
    )


class _ConfigLoaderAlert(ConfigBaseSettings):
    """Interface for loading Alert configuration."""

    enable: bool = Field(
        default=False,
        description="Whether to enable fetching Recorded Future alerts.",
    )
    default_opencti_severity: Literal["low", "medium", "high", "critical"] = Field(
        default="low",
        description="Default severity level for alerts imported into OpenCTI.",
    )
    priority_alerts_only: bool = Field(
        default=False,
        description="Whether to import only high-priority alerts.",
    )


class _ConfigLoaderPlaybookAlert(ConfigBaseSettings):
    """Interface for loading Playbook Alert configuration."""

    enable: bool = Field(
        default=False,
        description="Whether to enable fetching Recorded Future playbook alerts.",
    )
    severity_threshold_domain_abuse: Literal["Informational", "Moderate", "High"] = (
        Field(
            default="Informational",
            description="Minimum severity threshold for domain abuse playbook alerts.",
        )
    )
    severity_threshold_identity_novel_exposures: Literal[
        "Informational", "Moderate", "High"
    ] = Field(
        default="Informational",
        description="Minimum severity threshold for identity novel exposures playbook alerts.",
    )
    severity_threshold_code_repo_leakage: Literal[
        "Informational", "Moderate", "High"
    ] = Field(
        default="Informational",
        description="Minimum severity threshold for code repository leakage playbook alerts.",
    )
    debug: bool = Field(
        default=False,
        description="Whether to enable debug logging for playbook alerts.",
    )
