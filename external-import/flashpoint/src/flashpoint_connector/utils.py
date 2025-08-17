from validators import domain, ip_address


def is_ipv4(value: str) -> bool:
    """
    Return whether given value is a valid IPv4 address.
    """
    return ip_address.ipv4(value) is True


def is_ipv6(value: str) -> bool:
    """
    Return whether given value is a valid IPv6 address.
    """
    return ip_address.ipv6(value) is True


def is_domain(value: str) -> bool:
    """
    Return whether given value is a valid Domain name.
    """
    return domain(value) is True
