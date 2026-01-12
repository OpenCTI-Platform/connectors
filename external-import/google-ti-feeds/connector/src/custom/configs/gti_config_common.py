"""GTI configuration common utilities and constants.

This module defines common constants and utilities used across all GTI configuration modules.
"""

from typing import ClassVar

from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import Field, HttpUrl, SecretStr
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
    v: list[str], field_name: str, allowed_origins: list[str] | None = None
) -> list[str]:
    """Split and validate a comma-separated string into a list and validate its contents.

    Args:
        v: list of values to validate
        field_name: Name of the field for error messages
        allowed_origins: list of allowed values (defaults to ALLOWED_ORIGINS)

    Returns:
        list of validated origin strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    if allowed_origins is None:
        allowed_origins = ALLOWED_ORIGINS

    try:
        if not v:
            raise GTIConfigurationError(f"At least one {field_name} must be specified.")

        invalid = set(v) - set(allowed_origins)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(allowed_origins)}."
            )
        return v
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


def validate_report_types_list(
    v: list[str], field_name: str = "report type"
) -> list[str]:
    """Validate a list of report types against allowed values.

    Args:
        v: list of values to validate
        field_name: Name of the field for error messages

    Returns:
        list of validated report type strings

    Raises:
        GTIConfigurationError: If validation fails

    """
    try:
        if not v:
            raise GTIConfigurationError(f"At least one {field_name} must be specified.")

        invalid = set(v) - set(ALLOWED_REPORT_TYPES)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid {field_name}: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}."
            )
        return v
    except GTIConfigurationError:
        raise
    except Exception as e:
        raise GTIConfigurationError(f"Failed to validate {field_name}: {str(e)}") from e


class GTIBaseConfig(BaseConfig):
    """Base configuration class for GTI configurations."""

    yaml_section: ClassVar[str] = "gti"
    model_config = SettingsConfigDict(env_prefix="gti_", enable_decoding=False)

    api_key: SecretStr = Field(
        description="API key for authenticating with the Google Threat Intelligence service",
        min_length=1,
    )
    api_url: HttpUrl = Field(
        default=HttpUrl("https://www.virustotal.com/api/v3"),
        description="Base URL for the Google Threat Intelligence API",
    )
