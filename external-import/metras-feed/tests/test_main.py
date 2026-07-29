"""Unit tests for shared, dependency-free logic in the Metras Feed connector."""

from connector.utils import (
    is_mitre_attack_id,
    is_newer_than,
    is_valid_ipv4,
    is_valid_url,
    normalize_timestamp,
    refang,
    severity_to_score,
    stix_timestamp,
)


def test_refang():
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("hxxps://evil[.]com") == "https://evil.com"


def test_ipv4_validation():
    assert is_valid_ipv4("10.200.0.214")
    assert not is_valid_ipv4("not-an-ip")
    assert not is_valid_ipv4("2001:db8::1")


def test_url_validation():
    assert is_valid_url("https://example.com")
    assert not is_valid_url("example.com")


def test_mitre_ids():
    assert is_mitre_attack_id("T1059")
    assert is_mitre_attack_id("T1059.001")
    assert not is_mitre_attack_id("X1059")
    assert not is_mitre_attack_id("1059")


def test_severity_mapping():
    assert severity_to_score("Critical")[0] == 90
    assert severity_to_score(5)[0] == 90
    assert severity_to_score("unknown")[1] == "medium"


def test_timestamp_helpers():
    dt = normalize_timestamp("2025-11-11T11:36:20.162Z")
    assert dt is not None and dt.tzinfo is not None
    older = normalize_timestamp("2025-01-01T00:00:00Z")
    assert is_newer_than("2025-11-11T11:36:20Z", older)
    assert not is_newer_than("2024-01-01T00:00:00Z", dt)
    assert stix_timestamp(dt).endswith("Z")
