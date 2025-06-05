"""The module contains the ToolTypeOV enum class for representing various tool types in an OV context."""

from enum import Enum


class ToolTypeOV(str, Enum):
    """Tool Type OV Enum."""

    DENIAL_OF_SERVICE = "denial-of-service"
    EXPLOITATION = "exploitation"
    INFORMATION_GATHERING = "information-gathering"
    NETWORK_CAPTURE = "network-capture"
    CREDENTIAL_EXPLOITATION = "credential-exploitation"
    REMOTE_ACCESS = "remote-access"
    VULNERABILITY_SCANNING = "vulnerability-scanning"
    UNKNOWN = "unknown"
