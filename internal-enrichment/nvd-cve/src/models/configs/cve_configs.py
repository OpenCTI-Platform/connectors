from datetime import timedelta

from pydantic import (
    Field,
    PositiveInt,
    SecretStr,
    field_validator,
)
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderCVE(ConfigBaseSettings):
    """Interface for loading dedicated configuration."""

    # Config Loader
    base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves",
        description="URL for the CVE API.",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        description="API Key for the CVE API (optional for low-volume testing, recommended for production rate limits).",
    )
    create_unmatched_cve: bool = Field(
        default=True,
        description="If set to `True`, create a minimal placeholder Vulnerability entity even if NVD has not published data for the extracted CVE ID yet.",
    )
    create_relationships: bool = Field(
        default=True,
        description="If set to `True`, create `related-to` / `targets` relationships when linking extracted CVEs to containers or incidents in addition to `object_refs`.",
    )
    import_software: bool = Field(
        default=False,
        description="⚠️ WARNING: Enabling this option can lead to the ingestion "
        "of a VERY SIGNIFICANT volume of data into the platform. Each CVE may resolve "
        "to dozens of CPE matches, resulting in massive amounts of Software entities "
        "and relationships. Use with caution. If set to `True`, resolve CPEs "
        "associated with each CVE via the NVD CPE Match API and import them "
        "as Software objects with 'has' relationships to vulnerabilities.",
    )
    cpe_history_interval: timedelta | None = Field(
        default=timedelta(days=120),
        description="When import_software is enabled, The interval specifies how far "
        "back in time to search for CPEs that were modified within that period. "
        "This helps limit the number of CPEs resolved and imported. "
        "Maximum interval is 120 days. "
        "⚠️ WARNING: Null value will disable the time filter and may result in "
        "importing a very large number of CPEs. Use with caution.",
    )
    cpe_max_concurrency: PositiveInt = Field(
        default=10,
        description="Maximum number of concurrent CPE resolution tasks when import_software is enabled.",
    )

    cve_max_concurrency: PositiveInt = Field(
        default=50,
        description="Maximum number of concurrent CVE processing workers (bounds queued tasks and bundle sends).",
    )
    max_cves_per_entity: PositiveInt = Field(
        default=100,
        description="Maximum number of distinct CVE identifiers extracted and enriched from a single entity/container.",
    )

    @field_validator("cpe_history_interval")
    @classmethod
    def validate_cpe_history_interval(cls, value: timedelta | None) -> timedelta | None:
        if value is None:
            return value
        max_interval = timedelta(days=120)
        if value > max_interval:
            raise ValueError(f"cpe_history_interval cannot exceed {max_interval}.")
        return value
