"""The module contains the ReportTypeOV enum class for OpenVAS report types."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ReportTypeOV(BaseOV):
    """Report Type Enumeration."""

    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    IDENTITY = "identity"
    INDICATOR = "indicator"
    INTRUSION_SET = "intrusion-set"
    MALWARE = "malware"
    OBSERVED_DATA = "observed-data"
    THREAT_ACTOR = "threat-actor"
    THREAT_REPORT = "threat-report"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
