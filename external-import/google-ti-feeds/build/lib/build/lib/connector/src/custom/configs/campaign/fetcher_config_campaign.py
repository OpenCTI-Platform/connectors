"""GTI fetcher configurations for campaigns.

This module defines configurations for fetching campaign entities
from the Google Threat Intelligence API using the generic fetcher system.
"""

from connector.src.custom.exceptions import (
    GTICampaignFetchError,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    GTICampaignData,
    GTICampaignResponse,
)
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_MAIN_CAMPAIGN_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="campaigns",
    endpoint="/collections",
    display_name="campaigns",
    exception_class=GTICampaignFetchError,
    response_model=GTICampaignResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_CAMPAIGN_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="campaigns",
    endpoint="/collections/{entity_id}",
    display_name="campaigns",
    exception_class=GTICampaignFetchError,
    response_model=GTICampaignData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

CAMPAIGN_FETCHER_CONFIGS = {
    "main_campaigns": GTI_MAIN_CAMPAIGN_FETCHER_CONFIG,
    "campaigns": GTI_CAMPAIGN_FETCHER_CONFIG,
}
