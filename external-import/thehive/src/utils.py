import ipaddress


def is_ipv6(ip_str):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        ipaddress.IPv6Address(ip_str)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(ip_str, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(ip_str):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        ipaddress.IPv4Address(ip_str)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(ip_str, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False
