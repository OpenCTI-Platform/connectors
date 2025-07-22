from typing import Optional

from pydantic import (
    Field,
    PositiveInt,
    SecretStr,
)
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderCVE(ConfigBaseSettings):
    """Interface for loading ServiceNow dedicated configuration."""

    # Config Loader
    base_url: Optional[str] = Field(
        alias="CVE_BASE_URL",
        default="https://services.nvd.nist.gov/rest/json/cves",
        description="URL for the CVE API.",
    )
    api_key: SecretStr = Field(
        alias="CVE_API_KEY",
        description="API Key for the CVE API.",
    )
    interval: Optional[PositiveInt] = Field(
        alias="CVE_INTERVAL",
        default=6,
        description="Interval in hours to check and import new CVEs. Must be strictly greater than 1, advice from NIST minimum 2 hours.",
    )
    max_date_range: Optional[PositiveInt] = Field(
        alias="CVE_MAX_DATE_RANGE",
        default=120,
        description="Determines how many days to collect CVE. Maximum of 120 days.",
    )
    maintain_data: Optional[bool] = Field(
        alias="CVE_MAINTAIN_DATA",
        default=True,
        description="If set to `True`, import CVEs from the last run of the connector to the current time. Takes 2 values: `True` or `False`.",
    )
    pull_history: Optional[bool] = Field(
        alias="CVE_PULL_HISTORY",
        default=False,
        description="If set to `True`, import all CVEs from start year define in history start year configuration and history start year is required. Takes 2 values: `True` or `False`.",
    )
    history_start_year: Optional[PositiveInt] = Field(
        alias="CVE_HISTORY_START_YEAR",
        default=2019,
        description="Year in number. Required when pull_history is set to `True`.  Minimum 2019 as CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the cvssMetricV31 object.",
    )
