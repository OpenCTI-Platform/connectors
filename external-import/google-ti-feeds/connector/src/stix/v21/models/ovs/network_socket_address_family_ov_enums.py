"""The module defines the NetworkSocketAddressFamilyOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class NetworkSocketAddressFamilyOV(BaseOV):
    """Network Socket Address Family Enumeration."""

    AF_UNSPEC = "AF_UNSPEC"
    AF_INET = "AF_INET"
    AF_IPX = "AF_IPX"
    AF_APPLETALK = "AF_APPLETALK"
    AF_NETBIOS = "AF_NETBIOS"
    AF_INET6 = "AF_INET6"
    AF_IRDA = "AF_IRDA"
    AF_BTH = "AF_BTH"
