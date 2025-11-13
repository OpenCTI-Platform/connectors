"""GTI fetcher configurations for threat actors.

This module defines configurations for fetching threat actor entities
from the Google Threat Intelligence API using the generic fetcher system.
"""

from connector.src.custom.exceptions import (
    GTIActorFetchError,
)
from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
    GTIThreatActorResponse,
)
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_THREAT_ACTOR_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="threat_actors",
    endpoint="/collections/{entity_id}",
    display_name="threat actors",
    exception_class=GTIActorFetchError,
    response_model=GTIThreatActorData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_MAIN_THREAT_ACTOR_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="threat_actors",
    endpoint="/collections",
    display_name="Threat Actors",
    exception_class=GTIActorFetchError,
    response_model=GTIThreatActorResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

THREAT_ACTOR_FETCHER_CONFIGS = {
    "threat_actors": GTI_THREAT_ACTOR_FETCHER_CONFIG,
    "main_threat_actors": GTI_MAIN_THREAT_ACTOR_FETCHER_CONFIG,
}
