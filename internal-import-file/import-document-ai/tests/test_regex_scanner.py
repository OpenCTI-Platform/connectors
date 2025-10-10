"""
Unit tests for reportimporter.regex_scanner

These tests validate normalization and IOC scanning routines used to detect
and standardize structured observables (domains, IPs, hashes, etc.) from text.
They ensure that each normalization rule and regex pattern behaves as expected.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from reportimporter.regex_scanner import normalize_stix_value, scan_structured_iocs

# ----------------------------------------------------------------------------------
# Domain normalization tests
# ----------------------------------------------------------------------------------


def test_domain_normalization_basic():
    """Domains should lowercase and strip trailing dots."""
    result = normalize_stix_value("domain-name.value", "evil.com")
    assert result == "evil.com"


def test_domain_with_trailing_dot():
    """Trailing dots should be removed."""
    result = normalize_stix_value("domain-name.value", "evil.com.")
    assert result == "evil.com"


def test_invalid_domain():
    """Invalid domains should return the original unchanged."""
    result = normalize_stix_value("domain-name.value", "-invalid..com")
    assert result == "-invalid..com"


# ----------------------------------------------------------------------------------
# IP address normalization tests
# ----------------------------------------------------------------------------------


def test_ipv4_normalization():
    """IPv4 addresses should be preserved as-is."""
    result = normalize_stix_value("ipv4-addr.value", "192.168.1.1")
    assert result == "192.168.1.1"


def test_ipv6_normalization():
    """IPv6 addresses should be preserved as-is."""
    result = normalize_stix_value("ipv6-addr.value", "fe80::1")
    assert result == "fe80::1"


def test_ipv4_cidr():
    """IPv4 CIDR notation should be preserved."""
    result = normalize_stix_value("ipv4-cidr.value", "10.0.0.0/24")
    assert result == "10.0.0.0/24"


# ----------------------------------------------------------------------------------
# Email normalization tests
# ----------------------------------------------------------------------------------


def test_email_normalization():
    """Valid email addresses should lowercase the domain."""
    result = normalize_stix_value("email-addr.value", "user@example.com")
    assert result == "user@example.com"


def test_invalid_email():
    """Invalid email addresses should return as-is."""
    result = normalize_stix_value("email-addr.value", "bad@@example.com")
    assert result == "bad@@example.com"


# ----------------------------------------------------------------------------------
# Hash normalization tests
# ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hash_value,expected",
    [
        ("A" * 32, "a" * 32),
        ("B" * 40, "b" * 40),
        ("C" * 64, "c" * 64),
    ],
)
def test_hash_normalization(hash_value, expected):
    """File hashes should always lowercase their value."""
    result = normalize_stix_value("file.hashes.MD5", hash_value)
    assert result == expected


# ----------------------------------------------------------------------------------
# URL normalization tests
# ----------------------------------------------------------------------------------


def test_http_url():
    """URLs should be preserved as-is."""
    result = normalize_stix_value("url.value", "http://evil.com/path")
    assert result == "http://evil.com/path"


def test_url_with_query():
    """URLs containing query strings should remain unchanged."""
    result = normalize_stix_value("url.value", "https://evil.com/index.php?id=1")
    assert result == "https://evil.com/index.php?id=1"


def test_url_without_scheme():
    """URLs missing scheme should remain as raw input."""
    result = normalize_stix_value("url.value", "evil.com/path")
    assert result == "evil.com/path"


# ----------------------------------------------------------------------------------
# MAC address normalization tests
# ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("00:11:22:33:44:55", "00:11:22:33:44:55"),
        ("0011.2233.4455", "0011.2233.4455"),
        ("001122334455", "001122334455"),
    ],
)
def test_mac_normalization(mac, expected):
    """MAC addresses should be lowercased but not reformatted."""
    result = normalize_stix_value("mac-addr.value", mac)
    assert result == expected


# ----------------------------------------------------------------------------------
# IOC scanning tests
# ----------------------------------------------------------------------------------


def test_scan_structured_iocs_finds_domains_and_ips():
    """Structured IOC scan should find domains and IPv4 addresses."""
    text = "Detected C2 at evil.com and IP 10.0.0.5."
    result = list(scan_structured_iocs(text))
    labels = [s.type for s in result]
    values = [s.normalized_value for s in result]
    assert "Domain-Name.value" in labels
    assert "IPv4-Addr.value" in labels
    assert "evil.com" in values
    assert "10.0.0.5" in values


def test_scan_structured_iocs_finds_hashes():
    """Structured IOC scan should detect file hashes."""
    text = "MD5: d41d8cd98f00b204e9800998ecf8427e"
    result = list(scan_structured_iocs(text))
    labels = [s.type for s in result]
    values = [s.normalized_value for s in result]
    assert "File.hashes.MD5" in labels
    assert any(v.startswith("d41d8cd9") for v in values)


def test_scan_structured_iocs_returns_unique_ids():
    """Each unique IOC should have a unique deterministic ID."""
    text = "Evil IP: 1.2.3.4 repeated 1.2.3.4"
    result = list(scan_structured_iocs(text))
    ids = [s.id for s in result]
    assert len(ids) == len(set(ids))
