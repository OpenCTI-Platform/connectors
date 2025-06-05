"""The module defines an enumeration for network socket types."""

from enum import Enum


class NetworkSocketTypeOV(str, Enum):
    """Network Socket Type Enumeration."""

    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"
