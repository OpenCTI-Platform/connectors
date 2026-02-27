"""GTI converter configurations using the generic converter system.

This module defines the main CONVERTER_CONFIGS dictionary that combines all converter configurations
from the specialized modules.
"""

from connector.src.custom.configs.campaign.converter_config_campaign import (
    CAMPAIGN_CONVERTER_CONFIGS,
)
from connector.src.custom.configs.malware.converter_config_malware import (
    MALWARE_CONVERTER_CONFIGS,
)
from connector.src.custom.configs.report.converter_config_report import (
    REPORT_CONVERTER_CONFIGS,
)
from connector.src.custom.configs.threat_actor.converter_config_threat_actor import (
    THREAT_ACTOR_CONVERTER_CONFIGS,
)
from connector.src.custom.configs.vulnerability.converter_config_vulnerability import (
    VULNERABILITY_CONVERTER_CONFIGS,
)

CONVERTER_CONFIGS = {
    **REPORT_CONVERTER_CONFIGS,
    **THREAT_ACTOR_CONVERTER_CONFIGS,
    **MALWARE_CONVERTER_CONFIGS,
    **VULNERABILITY_CONVERTER_CONFIGS,
    **CAMPAIGN_CONVERTER_CONFIGS,
}
