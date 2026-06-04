"""GTI fetcher configurations for software toolkits.

This module defines configurations for fetching software toolkit entities
from the Google Threat Intelligence API using the generic fetcher system.
"""

from connector.src.custom.exceptions import (
    GTISoftwareToolkitFetchError,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
    GTISoftwareToolkitResponse,
)
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_MAIN_SOFTWARE_TOOLKIT_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="software_toolkits",
    endpoint="/collections",
    display_name="software toolkits",
    exception_class=GTISoftwareToolkitFetchError,
    response_model=GTISoftwareToolkitResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_SOFTWARE_TOOLKIT_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="software_toolkits",
    endpoint="/collections/{entity_id}",
    display_name="software toolkits",
    exception_class=GTISoftwareToolkitFetchError,
    response_model=GTISoftwareToolkitData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

SOFTWARE_TOOLKIT_FETCHER_CONFIGS = {
    "software_toolkits": GTI_SOFTWARE_TOOLKIT_FETCHER_CONFIG,
    "main_software_toolkits": GTI_MAIN_SOFTWARE_TOOLKIT_FETCHER_CONFIG,
}
