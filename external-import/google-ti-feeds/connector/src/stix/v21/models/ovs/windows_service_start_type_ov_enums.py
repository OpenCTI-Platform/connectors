"""The module defines the WindowsServiceStartTypeOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class WindowsServiceStartTypeOV(BaseOV):
    """Windows Service Start Type Enumeration."""

    SERVICE_AUTO_START = "SERVICE_AUTO_START"
    SERVICE_BOOT_START = "SERVICE_BOOT_START"
    SERVICE_DEMAND_START = "SERVICE_DEMAND_START"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    SERVICE_SYSTEM_ALERT = "SERVICE_SYSTEM_ALERT"
