import ipaddress
import re
from typing import Optional


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_domain_name(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" r"[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value or ""))


def is_hostname(value: str) -> bool:
    pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    return bool(re.match(pattern, value or ""))


def get_hash_type(hash_value: str) -> Optional[str]:
    length = len(hash_value or "")
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    if length == 128:
        return "SHA-512"
    return None


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def detect_observable_type(value: str) -> str:
    """Auto-detect the STIX observable type from a string value.

    Detection order (first match wins):
      IPv4-Addr  → valid IPv4 address
      IPv6-Addr  → valid IPv6 address
      Url        → starts with http:// or https://
      Email-Addr → matches simple email pattern (contains @ with domain)
      StixFile   → 32, 40, or 64 hex characters (MD5 / SHA-1 / SHA-256)
      Domain-Name → multi-label domain regex
      Text       → fallback (caller should log a warning)
    """
    if not value:
        return "Text"

    if is_ipv4(value):
        return "IPv4-Addr"

    if is_ipv6(value):
        return "IPv6-Addr"

    lower = value.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        return "Url"

    if _EMAIL_RE.match(value):
        return "Email-Addr"

    hex_len = len(value)
    if hex_len in (32, 40, 64) and _HEX_RE.match(value):
        return "StixFile"

    if is_domain_name(value):
        return "Domain-Name"

    return "Text"
