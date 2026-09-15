"""GTI configuration for reports.

This module defines configuration settings specific to GTI report imports.
"""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import (
    ALLOWED_ORIGINS,
    ALLOWED_REPORT_SUBENTITIES,
    ALLOWED_REPORT_TYPES,
    GTIBaseConfig,
    validate_origins_list,
    validate_report_types_list,
    validate_subentities_list,
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

    report_download_pdf: bool = Field(
        default=False,
        description="Whether to download report PDFs from the GTI API and attach them to the STIX Report objects in OpenCTI",
    )

    report_origins: ListFromString = Field(
        default=["google threat intelligence"],
        description="Comma-separated list of report origins to import, or 'All' for all origins. "
        f"Allowed values: {', '.join(ALLOWED_ORIGINS)}",
        examples=["All", "partner", "google threat intelligence", "crowdsourced"],
    )

    report_extra_filters: ListFromString = Field(
        default=[],
        description="Optional List of additional filters to add to query when fetching reports.",
        examples=["name:phishing"],
    )

    report_subentities: ListFromString = Field(
        default=[
            "malware_families",
            "threat_actors",
            "attack_techniques",
            "vulnerabilities",
            "campaigns",
            "domains",
            "files",
            "urls",
            "ip_addresses",
            "software_toolkits",
        ],
        description="Comma-separated list of sub-entity types to fetch and link for each report. "
        "An empty list disables sub-entity fetching entirely for reports, which can help reduce API quota usage. "
        f"Allowed values: {', '.join(ALLOWED_REPORT_SUBENTITIES)}",
        examples=["malware_families,threat_actors", ""],
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

    @field_validator("report_subentities", mode="after")
    @classmethod
    def validate_report_subentities(cls, v: list[str]) -> list[str]:
        """Validate report sub-entities against allowed values."""
        return validate_subentities_list(
            v, "report subentity", ALLOWED_REPORT_SUBENTITIES
        )
