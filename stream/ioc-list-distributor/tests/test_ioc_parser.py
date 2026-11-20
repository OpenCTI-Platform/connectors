"""Quick checks of the pattern parser. Run: python tests/test_ioc_parser.py (or pytest)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from connector.ioc_parser import OPENCTI_EXTENSION_ID, extract_iocs  # noqa: E402

SHA256 = "a" * 64
MD5 = "b" * 32


def indicator(pattern, **extra):
    data = {
        "type": "indicator",
        "id": "indicator--1",
        "pattern_type": "stix",
        "pattern": pattern,
    }
    data.update(extra)
    return data


def values(pattern, **extra):
    iocs, _ = extract_iocs(indicator(pattern, **extra))
    return sorted(iocs)


def test_single_values():
    assert values("[ipv4-addr:value = '1.2.3.4']") == [("ip", "ipv4", "1.2.3.4")]
    assert values("[ipv4-addr:value = '1.2.3.4/32']") == [("ip", "ipv4", "1.2.3.4")]
    assert values("[ipv4-addr:value = '45.0.0.0/8']") == [("ip", "ipv4", "45.0.0.0/8")]
    assert values("[ipv6-addr:value = '2001:db8::1']") == [
        ("ip", "ipv6", "2001:db8::1")
    ]
    assert values("[domain-name:value = 'Evil.COM.']") == [
        ("domain", "domain", "evil.com")
    ]
    assert values("[hostname:value = 'a.evil[.]com']") == [
        ("domain", "domain", "a.evil.com")
    ]
    assert values("[url:value = 'hxxp://Evil.com/Path?a=1']") == [
        ("url", "url", "http://evil.com/Path?a=1")
    ]
    assert values(f"[file:hashes.'SHA-256' = '{SHA256.upper()}']") == [
        ("hash", "sha256", SHA256)
    ]


def test_or_of_hashes():
    pattern = f"[file:hashes.MD5 = '{MD5}' OR file:hashes.'SHA-256' = '{SHA256}']"
    assert values(pattern) == sorted([("hash", "md5", MD5), ("hash", "sha256", SHA256)])


def test_skipped_patterns():
    for pattern in (
        "[ipv4-addr:value = '1.2.3.4' AND network-traffic:dst_port = 443]",
        "[url:value LIKE '%evil%']",
        "[ipv4-addr:value = '1.2.3.4'] WITHIN 300 SECONDS",
        "[domain-name:value = 'not a domain']",
        f"[file:hashes.'SHA-256' = '{'z' * 64}']",
    ):
        iocs, reason = extract_iocs(indicator(pattern))
        assert iocs == [] and reason, pattern
    iocs, reason = extract_iocs(
        indicator("rule x { condition: true }", pattern_type="yara")
    )
    assert iocs == [] and "yara" in reason


def test_name_fallback():
    ext = {"extensions": {OPENCTI_EXTENSION_ID: {"main_observable_type": "IPv4-Addr"}}}
    iocs, _ = extract_iocs(indicator("", name="5.6.7.8", **ext), name_fallback=True)
    assert iocs == [("ip", "ipv4", "5.6.7.8")]
    iocs, _ = extract_iocs(indicator("", name="Emotet C2", **ext), name_fallback=True)
    assert iocs == []
    iocs, _ = extract_iocs(indicator("", name="5.6.7.8", **ext), name_fallback=False)
    assert iocs == []


if __name__ == "__main__":
    test_single_values()
    test_or_of_hashes()
    test_skipped_patterns()
    test_name_fallback()
    print("All parser tests passed")
