"""GTI fetcher configurations using the generic fetcher system.

This module defines the main FETCHER_CONFIGS dictionary that combines all fetcher configurations
from the specialized modules.
"""

from connector.src.custom.configs.campaign.fetcher_config_campaign import (
    CAMPAIGN_FETCHER_CONFIGS,
)
from connector.src.custom.configs.fetcher_config_common import (
    COMMON_FETCHER_CONFIGS,
)
from connector.src.custom.configs.malware.fetcher_config_malware import (
    MALWARE_FETCHER_CONFIGS,
)
from connector.src.custom.configs.report.fetcher_config_report import (
    REPORT_FETCHER_CONFIGS,
)
from connector.src.custom.configs.threat_actor.fetcher_config_threat_actor import (
    THREAT_ACTOR_FETCHER_CONFIGS,
)
from connector.src.custom.configs.vulnerability.fetcher_config_vulnerability import (
    VULNERABILITY_FETCHER_CONFIGS,
)

FETCHER_CONFIGS = {
    **REPORT_FETCHER_CONFIGS,
    **THREAT_ACTOR_FETCHER_CONFIGS,
    **MALWARE_FETCHER_CONFIGS,
    **VULNERABILITY_FETCHER_CONFIGS,
    **CAMPAIGN_FETCHER_CONFIGS,
    **COMMON_FETCHER_CONFIGS,
}
