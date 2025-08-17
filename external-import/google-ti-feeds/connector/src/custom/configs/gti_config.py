"""GTI feed connector configuration—defines environment-based settings and validators.

This module combines all GTI configuration classes from the specialized modules
into a single GTIConfig class that inherits from all entity-specific configurations.
"""

from connector.src.custom.configs.malware.gti_config_malware import GTIMalwareConfig
from connector.src.custom.configs.report.gti_config_report import GTIReportConfig
from connector.src.custom.configs.threat_actor.gti_config_threat_actor import (
    GTIThreatActorConfig,
)


class GTIConfig(GTIReportConfig, GTIThreatActorConfig, GTIMalwareConfig):
    """Configuration for the GTI part of the connector.

    This class combines all entity-specific configurations through multiple inheritance,
    providing a unified configuration interface for the entire GTI connector.
    """

    pass
