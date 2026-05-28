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
        description="API Key for the CVE API.",
    )
    interval: PositiveInt = Field(
        default=6,
        description="Interval in hours to check and import new CVEs. Must be strictly greater than 1, advice from NIST minimum 2 hours.",
    )
    max_date_range: PositiveInt = Field(
        default=120,
        description="Determines how many days to collect CVE. Maximum of 120 days.",
    )
    maintain_data: bool = Field(
        default=True,
        description="If set to `True`, import CVEs from the last run of the connector to the current time. Takes 2 values: `True` or `False`.",
    )
    pull_history: bool = Field(
        default=False,
        description="If set to `True`, import all CVEs from start year define in history start year configuration and history start year is required. Takes 2 values: `True` or `False`.",
    )
    history_start_year: PositiveInt = Field(
        default=2019,
        description="Year in number. Required when pull_history is set to `True`.  Minimum 2019 as CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the cvssMetricV31 object.",
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

    @field_validator("cpe_history_interval")
    @classmethod
    def validate_cpe_history_interval(cls, value: timedelta | None) -> timedelta | None:
        if value is None:
            return value
        max_interval = timedelta(days=120)
        if value > max_interval:
            raise ValueError(f"cpe_history_interval cannot exceed {max_interval}.")
        return value
