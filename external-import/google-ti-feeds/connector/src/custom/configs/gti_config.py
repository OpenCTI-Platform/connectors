"""GTI feed connector configuration—defines environment-based settings and validators."""

from typing import ClassVar, List

from pydantic import field_validator
from pydantic_settings import SettingsConfigDict

from connector.src.octi.interfaces.base_config import BaseConfig

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


class GTIConfig(BaseConfig):
    """Configuration for the GTI part of the connector."""

    yaml_section: ClassVar[str] = "gti"
    model_config = SettingsConfigDict(env_prefix="gti_")

    api_key: str
    import_start_date: str = "P30D"
    api_url: str = "https://www.virustotal.com/api/v3"
    import_reports: bool = True
    report_types: List[str] | str = "All"
    origins: List[str] | str = "All"

    @field_validator("report_types", mode="before")
    @classmethod
    def split_and_validate(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        if isinstance(v, str):
            parts = [item.strip() for item in v.split(",") if item.strip()]

        if not parts:
            raise ValueError("At least one report type must be specified.")

        invalid = set(parts) - set(ALLOWED_REPORT_TYPES)
        if invalid:
            raise ValueError(
                f"Invalid report types: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}."
            )
        return parts

    @field_validator("origins", mode="before")
    @classmethod
    def split_and_validate_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        if isinstance(v, str):
            parts = [item.strip() for item in v.split(",") if item.strip()]

        if not parts:
            raise ValueError("At least one origin must be specified.")

        invalid = set(parts) - set(ALLOWED_ORIGINS)
        if invalid:
            raise ValueError(
                f"Invalid origins: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(ALLOWED_ORIGINS)}."
            )
        return parts
