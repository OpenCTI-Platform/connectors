"""Pure-function utilities for the Metras Feed connector.

No side effects, no HTTP, no STIX, no config access.
"""

import ipaddress
import re
from datetime import datetime, timezone

# Metras severity -> (OpenCTI x_opencti_score, OpenCTI severity label)
_SEVERITY_MAP = {
    "critical": (90, "critical"),
    "high": (75, "high"),
    "medium": (50, "medium"),
    "low": (25, "low"),
    "informational": (10, "low"),
    "info": (10, "low"),
}

# Numeric severity (threats/violations use 1-5)
_NUMERIC_SEVERITY = {
    5: (90, "critical"),
    4: (75, "high"),
    3: (50, "medium"),
    2: (25, "low"),
    1: (10, "low"),
}


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


# Expected hex length per hash algorithm (STIX 2.1 hash names).
_HASH_LENGTHS = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-512": 128}
_HEX = set("0123456789abcdefABCDEF")


def is_valid_hash(algo: str, value: str) -> bool:
    """True if ``value`` is a well-formed hex digest for ``algo`` (MD5/SHA-1/256/512).

    Guards STIX File creation against malformed hashes from the API, which would
    otherwise make stix2 raise and crash an import cycle.
    """
    length = _HASH_LENGTHS.get(algo)
    return (
        bool(value)
        and length is not None
        and len(value) == length
        and all(c in _HEX for c in value)
    )


def normalize_timestamp(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (Z or offset) into a tz-aware datetime."""
    if not ts:
        return None
    try:
        normalized = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def is_newer_than(timestamp_str: str | None, cutoff: datetime | None) -> bool:
    """True if ``timestamp_str`` is strictly newer than ``cutoff`` (or no cutoff)."""
    if cutoff is None:
        return True
    parsed = normalize_timestamp(timestamp_str)
    if parsed is None:
        return True
    return parsed > cutoff


def stix_timestamp(dt: datetime | None = None) -> str:
    """Return a Z-suffixed UTC timestamp acceptable to the stix2 library."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_to_score(severity: int | float | str | None) -> tuple[int, str]:
    """Map a Metras severity (string or 1-5 int) to (score, opencti_severity)."""
    if isinstance(severity, (int, float)):
        return _NUMERIC_SEVERITY.get(int(severity), (50, "medium"))
    if isinstance(severity, str):
        return _SEVERITY_MAP.get(severity.strip().lower(), (50, "medium"))
    return (50, "medium")


def is_mitre_attack_id(value: str) -> bool:
    """True for MITRE ATT&CK technique IDs like T1059 or T1059.001."""
    return bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", value or ""))
