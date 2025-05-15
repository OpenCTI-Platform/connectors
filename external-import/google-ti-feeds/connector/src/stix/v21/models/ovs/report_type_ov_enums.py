"""The module contains the ReportTypeOV enum class for OpenVAS report types."""

from enum import Enum


class ReportTypeOV(str, Enum):
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
