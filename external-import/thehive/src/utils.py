import ipaddress
from datetime import datetime


def format_datetime(timestamp, time_format):
    """formatting the date based on the provided timestamp and time_format."""
    return datetime.utcfromtimestamp(int(timestamp)).strftime(time_format)


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


def check_hash_type(value):
    """Check hash type based on length, this is not the best check. It's recommended to use file_<hash type> instead."""
    value_length = len(value)
    if value_length == 32:
        return "MD5"
    elif value_length == 40:
        return "SHA-1"
    elif value_length == 64:
        return "SHA-256"
    else:
        return "unknown-hash"
