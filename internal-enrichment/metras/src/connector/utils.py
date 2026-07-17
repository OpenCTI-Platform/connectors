"""Pure-function utilities for the Metras Enrichment connector.

No side effects, no HTTP, no STIX, no config access.
"""

import ipaddress


def refang(value: str) -> str:
    """Remove common defanging so values match the external API."""
    if not value:
        return value
    v = value
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    v = v.replace("hXXp://", "http://").replace("hXXps://", "https://")
    v = v.replace("[at]", "@").replace("[@]", "@")
    v = v.replace("[dot]", ".")
    return v.strip()


def is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def is_valid_url(value: str) -> bool:
    return isinstance(value, str) and value.startswith(("http://", "https://"))
