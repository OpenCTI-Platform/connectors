#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re
import ipaddress


def get_hash_type(value: str) -> str:
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", value):
        return "MD5"
    elif re.fullmatch(r"^[a-fA-F0-9]{40}$", value):
        return "SHA-1"
    elif re.fullmatch(r"^[a-fA-F0-9]{64}$", value):
        return "SHA-256"
    elif re.fullmatch(r"^[a-fA-F0-9]{128}$", value):
        return "SHA-512"
    return None


def is_ipv6(value):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        ipaddress.IPv6Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(value):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        ipaddress.IPv4Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_domain_name(value: str) -> bool:
    """Check if the value is a valid FQDN or domain name (not IP)."""
    pattern = r"^(?=.{1,253}$)(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$"
    return bool(re.fullmatch(pattern, value))


def is_hostname(value: str) -> bool:
    """
    Check if a string looks like a hostname.
    Examples: dc01.internal.local, server1, host-name-2
    """
    if not value or not isinstance(value, str):
        return False

    # Skip IP addresses
    if is_ipv4(value) or is_ipv6(value):
        return False

    # Match hostname patterns
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    return bool(re.match(hostname_pattern, value))
