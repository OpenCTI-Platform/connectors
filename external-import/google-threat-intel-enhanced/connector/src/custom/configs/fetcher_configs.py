"""GTI fetcher configurations using the generic fetcher system.

This module defines configurations for fetching different types of entities
from the Google Threat Intelligence API using the generic fetcher system.
"""

from connector.src.custom.exceptions import (
    GTIActorFetchError,
    GTICampaignFetchError,
    GTIDomainFetchError,
    GTIFileFetchError,
    GTIIPFetchError,
    GTIMalwareFetchError,
    GTIRelationshipFetchError,
    GTIReportFetchError,
    GTISoftwareToolkitFetchError,
    GTITechniqueFetchError,
    GTIUrlFetchError,
    GTIVulnerabilityFetchError,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    GTIAttackTechniqueData,
)
from connector.src.custom.models.gti_reports.gti_campaign_model import (
    GTICampaignData,
    GTICampaignResponse,
)
from connector.src.custom.models.gti_reports.gti_domain_model import (
    GTIDomainData,
)
from connector.src.custom.models.gti_reports.gti_file_model import (
    GTIFileData,
)
from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.custom.models.gti_reports.gti_malware_family_model import (
    GTIMalwareFamilyData,
    GTIMalwareFamilyResponse,
)
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportResponse
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
    GTIThreatActorResponse,
)
from connector.src.custom.models.gti_reports.gti_url_model import (
    GTIURLData,
)
from connector.src.custom.models.gti_reports.gti_vulnerability_model import (
    GTIVulnerabilityData,
    GTIVulnerabilityResponse,
)
from connector.src.custom.models.gti_reports.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
)
from connector.src.utils.fetchers.generic_fetcher_config import GenericFetcherConfig

GTI_REPORT_FETCHER_CONFIG = GenericFetcherConfig(
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

GTI_CAMPAIGN_FETCHER_CONFIG = GenericFetcherConfig(
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

GTI_CAMPAIGN_DETAIL_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="campaign_details",
    endpoint="/collections/{entity_id}",
    display_name="campaign details",
    display_name_singular="campaign detail",
    exception_class=GTICampaignFetchError,
    response_model=GTICampaignData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

# List-based fetcher configs for standalone imports (using /collections endpoint)
GTI_THREAT_ACTOR_LIST_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="threat_actors_list",
    endpoint="/collections",
    display_name="threat actors",
    exception_class=GTIActorFetchError,
    response_model=GTIThreatActorResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_MALWARE_LIST_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="malware_families_list",
    endpoint="/collections",
    display_name="malware families",
    display_name_singular="malware family",
    exception_class=GTIMalwareFetchError,
    response_model=GTIMalwareFamilyResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_VULNERABILITY_LIST_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="vulnerabilities_list",
    endpoint="/collections",
    display_name="vulnerabilities",
    display_name_singular="vulnerability",
    exception_class=GTIVulnerabilityFetchError,
    response_model=GTIVulnerabilityResponse,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_MALWARE_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="malware_families",
    endpoint="/collections/{entity_id}",
    display_name="malware families",
    display_name_singular="malware family",
    exception_class=GTIMalwareFetchError,
    response_model=GTIMalwareFamilyData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

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

GTI_ATTACK_TECHNIQUE_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="attack_techniques",
    endpoint="/attack_techniques/{entity_id}",
    display_name="attack techniques",
    exception_class=GTITechniqueFetchError,
    response_model=GTIAttackTechniqueData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_VULNERABILITY_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="vulnerabilities",
    endpoint="/collections/{entity_id}",
    display_name="vulnerabilities",
    display_name_singular="vulnerability",
    exception_class=GTIVulnerabilityFetchError,
    response_model=GTIVulnerabilityData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_SOFTWARE_TOOLKIT_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="software_toolkits",
    endpoint="/collections/{entity_id}",
    display_name="software toolkits",
    display_name_singular="software toolkit",
    exception_class=GTISoftwareToolkitFetchError,
    response_model=GTISoftwareToolkitData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_RELATIONSHIP_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="relationships",
    endpoint="/collections/{report_id}/relationships/{entity_type}",
    display_name="relationships",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_DOMAIN_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="domains",
    endpoint="/domains/{entity_id}",
    display_name="domains",
    exception_class=GTIDomainFetchError,
    response_model=GTIDomainData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_FILE_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="files",
    endpoint="/files/{entity_id}",
    display_name="files",
    exception_class=GTIFileFetchError,
    response_model=GTIFileData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_URL_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="urls",
    endpoint="/urls/{entity_id}",
    display_name="URLs",
    exception_class=GTIUrlFetchError,
    response_model=GTIURLData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

GTI_IP_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="ip_addresses",
    endpoint="/ip_addresses/{entity_id}",
    display_name="IP addresses",
    display_name_singular="IP address",
    exception_class=GTIIPFetchError,
    response_model=GTIIPData,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key="data",
)

# Observable-to-threat-actor relationship fetchers
GTI_DOMAIN_THREAT_ACTORS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="domain_threat_actors",
    endpoint="/domains/{entity_id}/threat_actors",
    display_name="domain threat actors",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_FILE_THREAT_ACTORS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="file_threat_actors",
    endpoint="/files/{entity_id}/threat_actors",
    display_name="file threat actors",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_URL_THREAT_ACTORS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="url_threat_actors",
    endpoint="/urls/{entity_id}/threat_actors",
    display_name="URL threat actors",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_IP_THREAT_ACTORS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="ip_threat_actors",
    endpoint="/ip_addresses/{entity_id}/threat_actors",
    display_name="IP threat actors",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

# Observable-to-malware relationship fetchers (collections = malware families)
GTI_DOMAIN_COLLECTIONS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="domain_collections",
    endpoint="/domains/{entity_id}/collections",
    display_name="domain malware collections",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_FILE_COLLECTIONS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="file_collections",
    endpoint="/files/{entity_id}/collections",
    display_name="file malware collections",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_URL_COLLECTIONS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="url_collections",
    endpoint="/urls/{entity_id}/collections",
    display_name="URL malware collections",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

GTI_IP_COLLECTIONS_FETCHER_CONFIG = GenericFetcherConfig(
    entity_type="ip_collections",
    endpoint="/ip_addresses/{entity_id}/collections",
    display_name="IP malware collections",
    exception_class=GTIRelationshipFetchError,
    response_model=None,
    method="GET",
    headers={"accept": "application/json"},
    timeout=60.0,
    response_key=None,
)

FETCHER_CONFIGS = {
    "reports": GTI_REPORT_FETCHER_CONFIG,
    "campaigns": GTI_CAMPAIGN_FETCHER_CONFIG,
    "campaign_details": GTI_CAMPAIGN_DETAIL_FETCHER_CONFIG,
    "threat_actors_list": GTI_THREAT_ACTOR_LIST_FETCHER_CONFIG,
    "malware_families_list": GTI_MALWARE_LIST_FETCHER_CONFIG,
    "vulnerabilities_list": GTI_VULNERABILITY_LIST_FETCHER_CONFIG,
    "malware_families": GTI_MALWARE_FETCHER_CONFIG,
    "threat_actors": GTI_THREAT_ACTOR_FETCHER_CONFIG,
    "attack_techniques": GTI_ATTACK_TECHNIQUE_FETCHER_CONFIG,
    "vulnerabilities": GTI_VULNERABILITY_FETCHER_CONFIG,
    "software_toolkits": GTI_SOFTWARE_TOOLKIT_FETCHER_CONFIG,
    "relationships": GTI_RELATIONSHIP_FETCHER_CONFIG,
    "domains": GTI_DOMAIN_FETCHER_CONFIG,
    "files": GTI_FILE_FETCHER_CONFIG,
    "urls": GTI_URL_FETCHER_CONFIG,
    "ip_addresses": GTI_IP_FETCHER_CONFIG,
    "domain_threat_actors": GTI_DOMAIN_THREAT_ACTORS_FETCHER_CONFIG,
    "file_threat_actors": GTI_FILE_THREAT_ACTORS_FETCHER_CONFIG,
    "url_threat_actors": GTI_URL_THREAT_ACTORS_FETCHER_CONFIG,
    "ip_threat_actors": GTI_IP_THREAT_ACTORS_FETCHER_CONFIG,
    "domain_collections": GTI_DOMAIN_COLLECTIONS_FETCHER_CONFIG,
    "file_collections": GTI_FILE_COLLECTIONS_FETCHER_CONFIG,
    "url_collections": GTI_URL_COLLECTIONS_FETCHER_CONFIG,
    "ip_collections": GTI_IP_COLLECTIONS_FETCHER_CONFIG,
}
