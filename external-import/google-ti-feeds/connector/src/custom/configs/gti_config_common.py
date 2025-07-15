"""GTI configuration common utilities and constants.

This module defines common constants and utilities used across all GTI configuration modules.
"""

from typing import ClassVar, List, Optional

from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.interfaces.base_config import BaseConfig
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


def validate_origins_list(
    v: str, field_name: str, allowed_origins: Optional[List[str]] = None
) -> List[str]:
    """Split and validate a comma-separated string into a list and validate its contents.

    Args:
        v: Input value to validate
        field_name: Name of the field for error messages
        allowed_origins: List of allowed values (defaults to ALLOWED_ORIGINS)

    Returns:
        List of validated origin strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    if allowed_origins is None:
        allowed_origins = ALLOWED_ORIGINS

    try:
        parts = None

        if isinstance(v, str):
            parts = [item.strip() for item in v.split(",") if item.strip()]

        if not parts:
            raise GTIConfigurationError(f"At least one {field_name} must be specified.")

        invalid = set(parts) - set(allowed_origins)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(allowed_origins)}."
            )
        return parts
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


class GTIBaseConfig(BaseConfig):
    """Base configuration class for GTI configurations."""

    yaml_section: ClassVar[str] = "gti"
    model_config = SettingsConfigDict(env_prefix="gti_")

    api_key: str
    api_url: str = "https://www.virustotal.com/api/v3"
