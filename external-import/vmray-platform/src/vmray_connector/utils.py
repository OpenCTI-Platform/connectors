"""
Utility functions for the VMRay connector.

Includes functions for date formatting, IP address validation, and hash type checking.
"""

from datetime import datetime, timezone
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    NetmaskValueError,
)
from typing import Union


def parse_to_vmray_datetime(value: Union[str, datetime]) -> str:
    """
    Convert a date value into a UTC datetime string formatted for VMRay API.

    Supported input formats:
        - datetime object
        - ISO 8601 string
        - Short date string

    Returns:
        str: UTC datetime string in the format 'YYYY-MM-DDTHH:MM:SS'.

    Raises:
        ValueError: If the input value is not in a supported format.
    """
    dt = None

    if isinstance(value, datetime):
        dt = value.astimezone(timezone.utc)
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "")).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            try:
                dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

    if dt is None:
        raise ValueError(f"Unsupported date format: {value}")

    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def validate_ip_or_network(
    parse_ip: callable, parse_ip_network: callable, value: str
) -> bool:
    """
    Helper function to validate whether a string is a valid IP address
    or a valid IP network (range in CIDR notation).
    """
    try:
        parse_ip(value)
        return True
    except AddressValueError:
        try:
            parse_ip_network(value, strict=False)
            return True
        except (AddressValueError, NetmaskValueError):
            return False


def is_ipv4(ip_str: str) -> bool:
    """Check whether a string is a valid IPv4 address or IPv4 network."""
    return validate_ip_or_network(IPv4Address, IPv4Network, ip_str)


def is_ipv6(ip_str: str) -> bool:
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    return validate_ip_or_network(IPv6Address, IPv6Network, ip_str)
