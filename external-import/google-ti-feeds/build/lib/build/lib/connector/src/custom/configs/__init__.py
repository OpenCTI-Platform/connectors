"""GTI configuration modules for the Google Threat Intelligence connector.

This package contains configuration classes and settings for the GTI connector,
including API configuration, fetcher configurations, converter configurations,
and batch processor configurations.
"""

from connector.src.custom.configs.campaign.batch_processor_config_campaign import (
    CAMPAIGN_BATCH_PROCESSOR_CONFIG,
)
from connector.src.custom.configs.malware.batch_processor_config_malware import (
    MALWARE_FAMILY_BATCH_PROCESSOR_CONFIG,
)
from connector.src.custom.configs.report.batch_processor_config_report import (
    REPORT_BATCH_PROCESSOR_CONFIG,
)
from connector.src.custom.configs.threat_actor.batch_processor_config_threat_actor import (
    THREAT_ACTOR_BATCH_PROCESSOR_CONFIG,
)
from connector.src.custom.configs.vulnerability.batch_processor_config_vulnerability import (
    VULNERABILITY_BATCH_PROCESSOR_CONFIG,
)

from .converter_config import CONVERTER_CONFIGS
from .fetcher_config import FETCHER_CONFIGS
from .gti_config import GTIConfig

__all__ = [
    "GTIConfig",
    "FETCHER_CONFIGS",
    "CONVERTER_CONFIGS",
    "REPORT_BATCH_PROCESSOR_CONFIG",
    "THREAT_ACTOR_BATCH_PROCESSOR_CONFIG",
    "MALWARE_FAMILY_BATCH_PROCESSOR_CONFIG",
    "VULNERABILITY_BATCH_PROCESSOR_CONFIG",
    "CAMPAIGN_BATCH_PROCESSOR_CONFIG",
]
