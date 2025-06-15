"""The module contains the WindowsIntegrityLevelOV enum class."""

from enum import Enum


class WindowsIntegrityLevelOV(str, Enum):
    """Windows Integrity Level Enumeration."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"
