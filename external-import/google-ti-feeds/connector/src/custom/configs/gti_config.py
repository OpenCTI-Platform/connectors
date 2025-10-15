"""GTI feed connector configuration—defines environment-based settings and validators.

This module combines all GTI configuration classes from the specialized modules
into a single GTIConfig class that inherits from all entity-specific configurations.
"""

from connector.src.custom.configs.campaign.gti_config_campaign import (
    GTICampaignConfig,
)
from connector.src.custom.configs.malware.gti_config_malware import GTIMalwareConfig
from connector.src.custom.configs.report.gti_config_report import GTIReportConfig
from connector.src.custom.configs.threat_actor.gti_config_threat_actor import (
    GTIThreatActorConfig,
)
from connector.src.custom.configs.vulnerability.gti_config_vulnerability import (
    GTIVulnerabilityConfig,
)


class GTIConfig(
    GTIReportConfig,
    GTIThreatActorConfig,
    GTIMalwareConfig,
    GTIVulnerabilityConfig,
    GTICampaignConfig,
):
    """Unified configuration for the Google Threat Intelligence (GTI) connector.

    This class combines all entity-specific configurations through multiple inheritance,
    providing a unified configuration interface for the entire GTI connector. It includes
    settings for:

    - Report imports (from GTIReportConfig)
    - Threat actor imports (from GTIThreatActorConfig)
    - Malware family imports (from GTIMalwareConfig)
    - Vulnerability imports (from GTIVulnerabilityConfig)
    - Campaign imports (from GTICampaignConfig)
    - Base GTI API settings (from GTIBaseConfig via inheritance)

    The configuration supports both YAML file-based and environment variable-based
    configuration, with environment variables taking precedence. All GTI-specific
    environment variables should be prefixed with 'gti_'.

    Examples
    --------
    Basic usage with environment variables:
        export gti_api_key="your-api-key"
        export gti_import_reports=true
        export gti_report_types="Actor Profile,Malware Profile"

    YAML configuration:
        gti:
          api_key: "your-api-key"
          import_reports: true
          report_types: "Actor Profile,Malware Profile"
          import_threat_actors: false
          import_malware_families: false

    """

    pass
