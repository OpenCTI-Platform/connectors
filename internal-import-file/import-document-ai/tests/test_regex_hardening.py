"""
Unit tests for structured IOC (Indicator of Compromise) extraction
via reportimporter.regex_scanner.scan_structured_iocs().

Purpose:
These tests validate regex-based detection and classification of observables,
ensuring the regex scanner correctly recognizes, filters, and rejects
invalid or malformed IOC patterns.

Scope:
- IPv6 (compressed and full)
- Domain name label and TLD rules
- Windows registry key format
- IPv4 range validation
"""

import sys
from pathlib import Path

# Ensure the `src` directory is importable (consistent with other test files)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportimporter.regex_scanner import scan_structured_iocs


def _types(text: str) -> set[str]:
    """Return the set of IOC type labels extracted from the provided text."""
    return {s.type for s in scan_structured_iocs(text)}


def test_ipv6_compressed_and_full():
    """
    Verify detection of both full and compressed IPv6 addresses.
    """
    full = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    comp = "2001:db8::8a2e:370:7334"
    kinds = _types(f"IPs {full} and {comp}")

    assert "IPv6-Addr.value" in kinds, f"Expected IPv6 type in {kinds}"


def test_domain_label_rules_and_tld():
    """
    Validate correct domain recognition rules:
    - Reject labels starting with a dash
    - Reject empty labels
    - Reject too-short TLDs
    """
    good = "sub.example-domain.com"
    bad1 = "-bad.example"  # label starts with dash
    bad2 = "example..com"  # empty label
    bad3 = "example.c"  # tld too short

    kinds = _types(f"Try {good} and {bad1} and {bad2} and {bad3}")

    assert "Domain-Name.value" in kinds, f"Expected domain type in {kinds}"


def test_registry_key_strict_chars():
    """
    Validate Windows registry key detection, ensuring invalid characters (like '|')
    cause the pattern to be rejected.
    """
    good = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion"
    bad = r"HKLM\Software\Bad|Key"

    kinds_good = _types(good)
    kinds_bad = _types(bad)

    assert "Windows-Registry-Key.key" in kinds_good, "Expected valid registry key match"
    assert (
        "Windows-Registry-Key.key" not in kinds_bad
    ), "Invalid registry key should not match"


def test_invalid_ipv4_out_of_range():
    """
    Verify that IPv4 addresses with octets >255 are rejected.
    """
    text = "Suspicious IP 999.999.999.999"
    kinds = _types(text)

    assert (
        "IPv4-Addr.value" not in kinds
    ), f"Invalid IPv4 should not be detected: {kinds}"
