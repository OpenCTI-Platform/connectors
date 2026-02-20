"""GTI configuration for reports.

This module defines configuration settings specific to GTI report imports.
"""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    ALLOWED_REPORT_TYPES,
    GTIBaseConfig,
    validate_origins_list,
    validate_report_types_list,
)
from connectors_sdk import ListFromString
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

    report_types: ListFromString = Field(
        default=["All"],
        description="Comma-separated list of report types to import, or 'All' for all types. "
        f"Allowed values: {', '.join(ALLOWED_REPORT_TYPES)}",
        examples=["All", "Actor Profile,Malware Profile", "Threat Activity Alert"],
    )

    report_origins: ListFromString = Field(
        default=["google threat intelligence"],
        description="Comma-separated list of report origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner,google threat intelligence", "crowdsourced"],
    )

    @field_validator("report_types", mode="after")
    @classmethod
    def validate_report_types(cls, v: list[str]) -> list[str]:
        """Validate report types against allowed values."""
        return validate_report_types_list(v, "report type")

    @field_validator("report_origins", mode="after")
    @classmethod
    def validate_report_origins(cls, v: list[str]) -> list[str]:
        """Validate report origins against allowed values."""
        return validate_origins_list(v, "report origin", ALLOWED_ORIGINS)
