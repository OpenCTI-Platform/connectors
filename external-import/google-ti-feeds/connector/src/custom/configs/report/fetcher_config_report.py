"""GTI fetcher configurations for reports.

This module defines configurations for fetching report entities
from the Google Threat Intelligence API using the generic fetcher system.
"""

from connector.src.custom.exceptions import (
    GTIReportFetchError,
)
from connector.src.custom.models.gti.gti_report_model import (
    GTIReportData,
    GTIReportResponse,
)
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_MAIN_REPORT_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="reports",
    endpoint="/collections",
    display_name="reports",
    exception_class=GTIReportFetchError,
    response_model=GTIReportResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_REPORT_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="reports",
    endpoint="/collections/{entity_id}",
    display_name="reports",
    exception_class=GTIReportFetchError,
    response_model=GTIReportData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

REPORT_FETCHER_CONFIGS = {
    "main_reports": GTI_MAIN_REPORT_FETCHER_CONFIG,
    "reports": GTI_REPORT_FETCHER_CONFIG,
}
