"""GTI configuration for reports.

This module defines configuration settings specific to GTI report imports.
"""

from datetime import timedelta
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
from pydantic import Field, field_validator


class GTIReportConfig(GTIBaseConfig):
    """Configuration for GTI report imports."""

    report_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import reports (e.g., P1D for 1 day, P7D for 7 days)",
    )

    import_reports: bool = Field(
        default=True,
        description="Whether to enable importing report data from GTI",
    )

    report_types: List[str] | str = Field(
        default="All",
        description="Comma-separated list of report types to import, or 'All' for all types. "
        f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}",
        examples=["All", "Actor Profile,Malware Profile", "Threat Activity Alert"],
    )

    report_origins: List[str] | str = Field(
        default="google threat intelligence",
        description="Comma-separated list of report origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner,google threat intelligence", "crowdsourced"],
    )

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
