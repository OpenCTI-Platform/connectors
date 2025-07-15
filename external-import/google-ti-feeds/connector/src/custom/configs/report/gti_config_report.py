"""GTI configuration for reports.

This module defines configuration settings specific to GTI report imports.
"""

from typing import List

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    ALLOWED_REPORT_TYPES,
    GTIBaseConfig,
    validate_origins_list,
)
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from pydantic import field_validator


class GTIReportConfig(GTIBaseConfig):
    """Configuration for GTI report imports."""

    report_import_start_date: str = "P1D"
    import_reports: bool = True
    report_types: List[str] | str = "All"
    report_origins: List[str] | str = "All"

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

    @field_validator("report_origins", mode="before")
    @classmethod
    def split_and_validate_report_origins(cls, v: str) -> List[str]:
        """Split and validate a comma-separated string into a list and validate its contents."""
        return validate_origins_list(v, "report origin", ALLOWED_ORIGINS)
