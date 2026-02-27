"""The module contains the WindowsServiceStatusOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class WindowsServiceStatusOV(BaseOV):
    """Windows Service Status Enumeration."""

    SERVICE_CONTINUE_PENDING = "SERVICE_CONTINUE_PENDING"
    SERVICE_PAUSE_PENDING = "SERVICE_PAUSE_PENDING"
    SERVICE_PAUSED = "SERVICE_PAUSED"
    SERVICE_RUNNING = "SERVICE_RUNNING"
    SERVICE_START_PENDING = "SERVICE_START_PENDING"
    SERVICE_STOP_PENDING = "SERVICE_STOP_PENDING"
    SERVICE_STOPPED = "SERVICE_STOPPED"
