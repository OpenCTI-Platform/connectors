"""STIX 2.1 single-observable pattern extraction shared by the ArcSight client."""

import re
from typing import Optional

# Single-observable STIX 2.1 patterns whose value can be pushed to an ArcSight
# Active List. Active lists are generic key/value stores, so IP addresses,
# domains, URLs and file hashes are all supported.
SUPPORTED_STIX_PATTERNS = [
    re.compile(r"^\s*\[ipv4-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[ipv6-addr:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[domain-name:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(r"^\s*\[url:value\s*=\s*'([^']+)'\s*\]\s*$"),
    re.compile(
        r"^\s*\[file:hashes\.(?i:'?(?:MD5|SHA-?1|SHA-?256)'?)\s*=\s*'([^']+)'\s*\]\s*$"
    ),
]


def extract_value(pattern: str) -> Optional[str]:
    """Return the observable value of a supported single-observable STIX pattern, or None."""
    if not pattern:
        return None
    for regex in SUPPORTED_STIX_PATTERNS:
        match = regex.match(pattern)
        if match:
            return match.group(1)
    return None
