"""The module defines an enumeration for Windows service types."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class WindowsServiceTypeOV(BaseOV):
    """Windows Service Type Enumeration."""

    SERVICE_KERNEL_DRIVER = "SERVICE_KERNEL_DRIVER"
    SERVICE_FILE_SYSTEM_DRIVER = "SERVICE_FILE_SYSTEM_DRIVER"
    SERVICE_WIN32_OWN_PROCESS = "SERVICE_WIN32_OWN_PROCESS"
    SERVICE_WIN32_SHARE_PROCESS = "SERVICE_WIN32_SHARE_PROCESS"
