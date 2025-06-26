"""The module defines an enumeration for network socket types."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class NetworkSocketTypeOV(BaseOV):
    """Network Socket Type Enumeration."""

    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"
