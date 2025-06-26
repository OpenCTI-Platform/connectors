"""The module contains the ToolTypeOV enum class for representing various tool types in an OV context."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class ToolTypeOV(BaseOV):
    """Tool Type OV Enum."""

    DENIAL_OF_SERVICE = "denial-of-service"
    EXPLOITATION = "exploitation"
    INFORMATION_GATHERING = "information-gathering"
    NETWORK_CAPTURE = "network-capture"
    CREDENTIAL_EXPLOITATION = "credential-exploitation"
    REMOTE_ACCESS = "remote-access"
    VULNERABILITY_SCANNING = "vulnerability-scanning"
    UNKNOWN = "unknown"
