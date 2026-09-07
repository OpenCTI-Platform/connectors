import ipaddress
import urllib.parse
from typing import Any, Dict, List


def is_valid_ipv4(value: str) -> bool:
    """
    Check if a given string is a valid IPv4 address.

    Args:
        value: The string to validate.

    Returns:
        True if the string is a valid IPv4 address, False otherwise.
    """
    if not value:
        return False
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except ipaddress.AddressValueError:
        return False


def normalize_host(host: str) -> str:
    """
    Clean and normalize a host domain name.
    Trims whitespaces and converts to lowercase. If the host is accidentally
    provided as a URL, extracts the hostname.

    Args:
        host: The host string to normalize.

    Returns:
        The normalized host domain name, or an empty string if invalid.
    """
    if not host or not isinstance(host, str):
        return ""

    host = host.strip().lower()

    # If it looks like a URL, extract the host part
    if "://" in host:
        try:
            parsed = urllib.parse.urlparse(host)
            if parsed.hostname:
                host = parsed.hostname
        except Exception:
            pass

    # Remove trailing port if any (e.g. example.com:443)
    if ":" in host:
        host = host.split(":")[0]

    return host


def group_targets_by_host(targets: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group raw targets by normalized host domain name.
    Extracts and deduplicates valid IPv4 addresses for each domain.

    Args:
        targets: A list of raw target dictionaries.

    Returns:
        A dictionary mapping each normalized host to its aggregated targets:
        {
            "example.com": {
                "host": "example.com",
                "ips": ["192.0.2.1", "192.0.2.2"],
                "raw_targets": [...]
            }
        }
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for target in targets:
        if not isinstance(target, dict):
            continue

        raw_host = target.get("host")
        host = normalize_host(raw_host)

        if not host:
            continue

        # Initialize the host aggregate if not present
        if host not in aggregated:
            aggregated[host] = {
                "host": host,
                "ips": set(),
                "raw_targets": [],
            }

        # Add raw target
        aggregated[host]["raw_targets"].append(target)

        # Handle IP validation & deduplication
        ip_val = target.get("ip")
        if isinstance(ip_val, str) and is_valid_ipv4(ip_val):
            aggregated[host]["ips"].add(ip_val.strip())

    # Convert sets to sorted lists for deterministic outputs
    for host_data in aggregated.values():
        host_data["ips"] = sorted(list(host_data["ips"]))

    return aggregated
