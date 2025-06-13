"""The module defines the WindowsServiceStartTypeOV enum class."""

from enum import Enum


class WindowsServiceStartTypeOV(str, Enum):
    """Windows Service Start Type Enumeration."""

    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"
