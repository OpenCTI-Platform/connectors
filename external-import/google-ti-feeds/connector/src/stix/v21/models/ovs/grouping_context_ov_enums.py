"""The module contains the GroupingContextOV enum class."""

from enum import Enum


class GroupingContextOV(str, Enum):
    """Grouping Context Enumeration."""

    SUSPICIOUS_ACTIVITY = "suspicious-activity"
    MALWARE_ANALYSIS = "malware-analysis"
    UNSPECIFIED = "unspecified"
