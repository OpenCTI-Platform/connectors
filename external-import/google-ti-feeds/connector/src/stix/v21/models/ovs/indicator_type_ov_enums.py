"""The module contains the IndicatorTypeOV enum class."""

from enum import Enum


class IndicatorTypeOV(str, Enum):
    """Indicator Type Enumeration."""

    ANOMALOUS_ACTIVITY = "anomalous-activity"
    ANONYMIZATION = "anonymization"
    BENIGN = "benign"
    COMPROMISED = "compromised"
    MALICIOUS_ACTIVITY = "malicious-activity"
    ATTRIBUTION = "attribution"
    UNKNOWN = "unknown"
