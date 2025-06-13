"""The module contains the IndicatorTypeOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class IndicatorTypeOV(BaseOV):
    """Indicator Type Enumeration."""

    ANOMALOUS_ACTIVITY = "anomalous-activity"
    ANONYMIZATION = "anonymization"
    BENIGN = "benign"
    COMPROMISED = "compromised"
    MALICIOUS_ACTIVITY = "malicious-activity"
    ATTRIBUTION = "attribution"
    UNKNOWN = "unknown"
