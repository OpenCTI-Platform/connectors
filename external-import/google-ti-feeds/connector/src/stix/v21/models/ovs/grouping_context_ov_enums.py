"""The module contains the GroupingContextOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class GroupingContextOV(BaseOV):
    """Grouping Context Enumeration."""

    SUSPICIOUS_ACTIVITY = "suspicious-activity"
    MALWARE_ANALYSIS = "malware-analysis"
    UNSPECIFIED = "unspecified"
