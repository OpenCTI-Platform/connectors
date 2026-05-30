"""IOC extraction from text content using ioc-finder."""

import ipaddress
from typing import NamedTuple

from ioc_finder import find_iocs as _find_iocs

# Mapping from ioc-finder dict keys to our IOC type names.
_IOC_FINDER_KEY_MAP = {
    "ipv4s": "ipv4",
    "ipv6s": "ipv6",
    "domains": "domain",
    "urls": "url",
    "md5s": "md5",
    "sha1s": "sha1",
    "sha256s": "sha256",
}

VALID_IOC_TYPES = frozenset(_IOC_FINDER_KEY_MAP.values())


class ExtractedIOC(NamedTuple):
    """Represents an extracted IOC."""

    type: str  # ipv4, ipv6, domain, url, md5, sha1, sha256
    value: str


def _is_valid_public_ip(value: str) -> bool:
    """Return True if *value* is a globally routable IP address."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract_iocs(text: str, ioc_types: list[str]) -> list[ExtractedIOC]:
    """Extract IOCs of the requested types from text.

    Args:
        text: The text content to parse.
        ioc_types: Which IOC types to extract (e.g. ["ipv4", "domain", "sha256"]).

    Returns:
        Deduplicated list of ExtractedIOC instances.
    """
    if not text or not ioc_types:
        return []

    raw = _find_iocs(
        text=text,
        parse_domain_from_url=False,
        parse_from_url_path=False,
        parse_domain_from_email_address=False,
        parse_address_from_cidr=False,
        parse_domain_name_from_xmpp_address=False,
        parse_urls_without_scheme=True,
    )

    results: dict[tuple[str, str], ExtractedIOC] = {}

    for finder_key, ioc_type in _IOC_FINDER_KEY_MAP.items():
        if ioc_type not in ioc_types:
            continue

        for value in raw.get(finder_key, []):
            # Filter non-public IPs.
            if ioc_type in ("ipv4", "ipv6") and not _is_valid_public_ip(value):
                continue

            # Deduplicate (case-insensitive except for URLs).
            key = (ioc_type, value.lower() if ioc_type != "url" else value)
            if key not in results:
                results[key] = ExtractedIOC(type=ioc_type, value=value)

    return list(results.values())
