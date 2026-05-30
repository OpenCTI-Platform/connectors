"""GTI fetcher configurations for IOC indicators.

This module defines configurations for fetching IOC delta packages
from the Google Threat Intelligence Steady-State IOC Deltas API.
"""

from connector.src.custom.exceptions import GTIIndicatorFetchError
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_IOC_DELTA_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="ioc_deltas",
    endpoint="/collections/sync/ioc-deltas/{package_id}",
    display_name="IOC delta packages",
    display_name_singular="IOC delta package",
    exception_class=GTIIndicatorFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/octet-stream"},
    timeout=120.0,
    response_key=None,
)

INDICATOR_FETCHER_CONFIGS = {
    "ioc_deltas": GTI_IOC_DELTA_FETCHER_CONFIG,
}
