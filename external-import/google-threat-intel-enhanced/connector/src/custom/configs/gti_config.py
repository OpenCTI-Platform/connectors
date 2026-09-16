"""GTI feed connector configuration—defines environment-based settings and validators."""

from typing import ClassVar, List

from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import field_validator
from pydantic_settings import SettingsConfigDict

ALLOWED_REPORT_TYPES = [
    "All",
    "Actor Profile",
    "Country Profile",
    "Cyber Physical Security Roundup",
    "Event Coverage/Implication",
    "Industry Reporting",
    "Malware Profile",
    "Net Assessment",
    "Network Activity Reports",
    "News Analysis",
    "OSINT Article",
    "Patch Report",
    "Strategic Perspective",
    "TTP Deep Dive",
    "Threat Activity Alert",
    "Threat Activity Report",
    "Trends and Forecasting",
    "Weekly Vulnerability Exploitation Report",
]

ALLOWED_ORIGINS = [
    "All",
    "partner",
    "crowdsourced",
    "google threat intelligence",
]

ALLOWED_INDICATOR_SCORING = [
    "gti_derived",
    "average_detection",
]


class GTIConfig(BaseConfig):
    """Configuration for the GTI part of the connector."""

    yaml_section: ClassVar[str] = "gti"
    model_config = SettingsConfigDict(env_prefix="gti_")

    api_key: str
    import_start_date: str = "P1D"
    api_url: str = "https://www.virustotal.com/api/v3"
    x_tool: str = "OpenCTI.GTIConnector.v1.0"
    import_reports: bool = True
    import_campaigns: bool = False
    import_threat_actors: bool = False
    import_malware_families: bool = False
    import_vulnerabilities: bool = False
    report_types: List[str] | str = "All"
    origins: List[str] | str = "All"
    campaign_origins: List[str] | str = "google threat intelligence"
    threat_actor_origins: List[str] | str = "google threat intelligence"
    malware_family_origins: List[str] | str = "google threat intelligence"
    vulnerability_origins: List[str] | str = "google threat intelligence"
    indicator_scoring: str = "gti_derived"
    enrich_iocs_with_threat_actors_and_malware: bool = False
    ioc_enrichment_threshold: int = 250

    @field_validator("indicator_scoring", mode="before")
    @classmethod
    def validate_indicator_scoring(cls, v: str) -> str:
        """Validate indicator_scoring option."""
        try:
            if not isinstance(v, str):
                raise GTIConfigurationError(
                    "indicator_scoring must be a string."
                )
            value = v.strip().lower()
            if value not in ALLOWED_INDICATOR_SCORING:
                raise GTIConfigurationError(
                    f"Invalid indicator_scoring: {v}. "
                    f"Allowed values: {', '.join(ALLOWED_INDICATOR_SCORING)}."
                )
            return value
        except GTIConfigurationError:
            raise
        except Exception as e:
            raise GTIConfigurationError(
                f"Failed to validate indicator_scoring: {str(e)}"
            ) from e

    @field_validator("report_types", mode="before")
    @classmethod
    def split_and_validate(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        try:
            parts = None

            if isinstance(v, str):
                parts = [item.strip() for item in v.split(",") if item.strip()]

            if not parts:
                raise GTIConfigurationError(
                    "At least one report type must be specified."
                )

            invalid = set(parts) - set(ALLOWED_REPORT_TYPES)
            if invalid:
                raise GTIConfigurationError(
                    f"Invalid report types: {', '.join(invalid)}. "
                    f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}."
                )
            return parts
        except GTIConfigurationError:
            raise
        except Exception as e:
            raise GTIConfigurationError(
                f"Failed to validate report types: {str(e)}"
            ) from e

    @field_validator("origins", mode="before")
    @classmethod
    def split_and_validate_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        try:
            parts = None

            if isinstance(v, str):
                parts = [item.strip() for item in v.split(",") if item.strip()]

            if not parts:
                raise GTIConfigurationError("At least one origin must be specified.")

            invalid = set(parts) - set(ALLOWED_ORIGINS)
            if invalid:
                raise GTIConfigurationError(
                    f"Invalid origins: {', '.join(invalid)}. "
                    f"Allowed values: {', '.join(ALLOWED_ORIGINS)}."
                )
            return parts
        except GTIConfigurationError:
            raise
        except Exception as e:
            raise GTIConfigurationError(f"Failed to validate origins: {str(e)}") from e

    @field_validator(
        "campaign_origins",
        "threat_actor_origins",
        "malware_family_origins",
        "vulnerability_origins",
        mode="before",
    )
    @classmethod
    def split_and_validate_entity_origins(cls, v: str) -> List[str]:
        """Split and validate entity-specific origins."""
        try:
            parts = None

            if isinstance(v, str):
                parts = [item.strip() for item in v.split(",") if item.strip()]

            if not parts:
                raise GTIConfigurationError("At least one origin must be specified.")

            invalid = set(parts) - set(ALLOWED_ORIGINS)
            if invalid:
                raise GTIConfigurationError(
                    f"Invalid origins: {', '.join(invalid)}. "
                    f"Allowed values: {', '.join(ALLOWED_ORIGINS)}."
                )
            return parts
        except GTIConfigurationError:
            raise
        except Exception as e:
            raise GTIConfigurationError(f"Failed to validate origins: {str(e)}") from e
