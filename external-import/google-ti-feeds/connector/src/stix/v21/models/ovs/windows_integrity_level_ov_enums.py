"""The module contains the WindowsIntegrityLevelOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class WindowsIntegrityLevelOV(BaseOV):
    """Windows Integrity Level Enumeration."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"
