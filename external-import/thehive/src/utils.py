import ipaddress


def is_ipv6(ip_str):
    """Determine whether the provided IP string is IPv6."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv4(ip_str):
    """Determine whether the provided IP string is IPv6."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False
