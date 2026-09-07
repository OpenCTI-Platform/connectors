"""Unit tests for reportimporter.regex_scanner normalization, scanning and hints."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.regex_scanner import (
    _make_id,
    _short_hash,
    build_hints_from_spans,
    normalize_stix_value,
    scan_structured_iocs,
)


class TestNormalizeStixValue:
    @pytest.mark.parametrize(
        "stix_type,value,expected",
        [
            ("x509-certificate.sha1_fingerprint", "AB:CD:EF", "abcdef"),
            ("x509-certificate.serial", "01 23:45", "012345"),
            ("file.hashes.MD5", "ABCDEF", "abcdef"),
            ("domain-name.value", "Example.COM.", "example.com"),
            ("url.value", "http://x.io/p", "http://x.io/p"),
            ("email-addr.value", "User@Example.com", "user@example.com"),
            ("ipv4-addr.value", "1.2.3.4", "1.2.3.4"),
            ("ipv4-cidr.value", "1.2.3.0 /24", "1.2.3.0/24"),
            ("autonomous-system.number", "AS123", "123"),
            ("autonomous-system.number", "ASfoo", "ASfoo"),
            ("mac-addr.value", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
            ("vulnerability.name", "cve-2021-1", "CVE-2021-1"),
            ("phone-number", "+442083661177", "+442083661177"),
            ("malware", "Emotet", "Emotet"),
        ],
    )
    def test_normalize(self, stix_type, value, expected):
        assert normalize_stix_value(stix_type, value) == expected

    def test_x509_dn_returns_string(self):
        out = normalize_stix_value("x509-certificate.issuer", "CN=Test, O=Org")
        assert isinstance(out, str)
        assert out


class TestIdHelpers:
    def test_short_hash_length(self):
        assert len(_short_hash("anything")) == 16

    def test_make_id_format(self):
        assert _make_id("domain-name.value", "example.com").startswith(
            "t=domain-name;h="
        )


class TestScanStructuredIocs:
    TEXT = (
        "Contact bad@evil.com from 8.8.8.8 visiting http://evil.com/x with hash "
        "d41d8cd98f00b204e9800998ecf8427e affected by CVE-2021-44228 via AS15169."
    )

    def test_finds_core_iocs(self):
        spans = scan_structured_iocs(self.TEXT)
        norms = {s.normalized_value for s in spans}
        assert "8.8.8.8" in norms
        assert "bad@evil.com" in norms
        assert "d41d8cd98f00b204e9800998ecf8427e" in norms
        assert "CVE-2021-44228" in norms

    def test_empty_text_returns_empty(self):
        assert scan_structured_iocs("") == []

    def test_spans_have_positions(self):
        spans = scan_structured_iocs(self.TEXT)
        assert spans
        for sp in spans:
            assert 0 <= sp.start < sp.end <= len(self.TEXT)


class TestBuildHintsFromSpans:
    def test_build_hints_structure(self):
        spans = scan_structured_iocs(TestScanStructuredIocs.TEXT)
        result = build_hints_from_spans(spans)
        assert "hints" in result
        assert result["hints"]
        for h in result["hints"]:
            assert {"id", "type", "category", "value", "positions"} <= set(h.keys())
            assert h["type"] in {"observable", "entity"}

    def test_max_hints_cap(self):
        spans = scan_structured_iocs(TestScanStructuredIocs.TEXT)
        result = build_hints_from_spans(spans, max_hints=2)
        assert len(result["hints"]) <= 2

    def test_duplicate_values_merge_positions(self):
        spans = scan_structured_iocs("8.8.8.8 and again 8.8.8.8")
        result = build_hints_from_spans(spans)
        ip_hints = [h for h in result["hints"] if h["value"] == "8.8.8.8"]
        assert len(ip_hints) == 1
        assert len(ip_hints[0]["positions"]) == 2

    def test_x509_serial_hint_is_observable(self):
        spans = scan_structured_iocs("Serial Number: 01:23:45")
        result = build_hints_from_spans(spans)
        serial_hints = [
            h for h in result["hints"] if h["category"] == "X509-Certificate.serial"
        ]
        assert serial_hints
        assert serial_hints[0]["type"] == "observable"
