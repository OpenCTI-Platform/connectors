"""Fuzz tests — throw malformed data at every parser.

Tests connector resilience against:
- Malformed/truncated JSON API responses
- Missing required fields
- Wrong types (str where int expected, etc.)
- Extremely large payloads
- None/null values in unexpected places
- Unicode edge cases
"""

import os
import sys

import pytest

SRC_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "src")
sys.path.insert(0, os.path.abspath(SRC_DIR))

from connector.scan_processor import ScanProcessor
from connector.sandbox_processor import SandboxProcessor

# ── Scan Processor Fuzz ──────────────────────────────────────────────────


class TestScanProcessorFuzz:
    """Scan processor must never crash on malformed input."""

    def test_none_input(self):
        assert ScanProcessor.process(None) is None

    def test_empty_dict(self):
        assert ScanProcessor.process({}) is None

    def test_string_input(self):
        """String instead of dict should not crash."""
        result = ScanProcessor.process("not a dict")
        assert result is None or isinstance(result, dict)

    def test_missing_polyscore(self):
        result = ScanProcessor.process({"assertions": [], "metadata": []})
        assert result is None or result.get("score", 0) == 0

    def test_polyscore_as_string(self):
        result = ScanProcessor.process({"polyscore": "not_a_number"})
        assert result is None or isinstance(result.get("score"), (int, float, type(None)))

    def test_polyscore_negative(self):
        result = ScanProcessor.process({"polyscore": -0.5})
        assert result is None or result.get("score", 0) >= 0

    def test_polyscore_over_one(self):
        result = ScanProcessor.process({"polyscore": 99.99})
        assert result is None or result.get("score", 0) <= 100

    def test_assertions_not_list(self):
        result = ScanProcessor.process({"polyscore": 0.5, "assertions": "wrong"})
        assert result is None or isinstance(result, dict)

    def test_metadata_not_list(self):
        result = ScanProcessor.process({"polyscore": 0.5, "metadata": 42})
        assert result is None or isinstance(result, dict)

    def test_nested_none_values(self):
        result = ScanProcessor.process(
            {
                "polyscore": 0.5,
                "assertions": [{"verdict": None, "author_name": None, "metadata": None}],
                "metadata": [{"tool": None, "tool_metadata": None}],
            }
        )
        assert result is None or isinstance(result, dict)

    def test_unicode_family_name(self):
        result = ScanProcessor.process(
            {
                "polyscore": 0.8,
                "metadata": [
                    {
                        "tool": "polyunite",
                        "tool_metadata": {
                            "malware_family": "恶意软件",
                            "labels": [],
                            "operating_system": [],
                        },
                    }
                ],
            }
        )
        assert result is None or isinstance(result, dict)

    def test_extremely_long_family_name(self):
        result = ScanProcessor.process(
            {
                "polyscore": 0.8,
                "metadata": [
                    {
                        "tool": "polyunite",
                        "tool_metadata": {
                            "malware_family": "A" * 100000,
                            "labels": [],
                            "operating_system": [],
                        },
                    }
                ],
            }
        )
        assert result is None or isinstance(result, dict)


# ── Sandbox Processor Fuzz ───────────────────────────────────────────────


class TestSandboxProcessorFuzz:
    """Sandbox processor must never crash on malformed input."""

    def test_none_input(self):
        assert SandboxProcessor.process(None) is None

    def test_empty_dict(self):
        assert SandboxProcessor.process({}) is None

    def test_string_input(self):
        result = SandboxProcessor.process("not a dict")
        assert result is None or isinstance(result, dict)

    def test_missing_report(self):
        result = SandboxProcessor.process({"sandbox": "triage"})
        assert result is None or isinstance(result, dict)

    def test_report_is_string(self):
        result = SandboxProcessor.process({"sandbox": "triage", "report": "wrong"})
        assert result is None or isinstance(result, dict)

    def test_report_targets_not_list(self):
        result = SandboxProcessor.process(
            {
                "sandbox": "triage",
                "report": {"targets": "not a list"},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_empty_targets(self):
        result = SandboxProcessor.process(
            {
                "sandbox": "triage",
                "report": {"targets": []},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_none_in_ttps(self):
        result = SandboxProcessor.process(
            {
                "sandbox": "triage",
                "report": {"targets": [{"score": 5, "iocs": {}}], "ttp": [None, "T1055", None]},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_domains_mixed_types(self):
        """Domains can be strings or dicts — processor must handle both."""
        result = SandboxProcessor.process(
            {
                "sandbox": "triage",
                "report": {
                    "targets": [
                        {
                            "score": 5,
                            "iocs": {
                                "domains": ["evil.com", {"domain": "bad.net"}, 42, None],
                                "ips": [],
                            },
                        }
                    ],
                    "ttp": [],
                },
            }
        )
        assert result is None or isinstance(result, dict)

    def test_cape_missing_malscore(self):
        result = SandboxProcessor.process(
            {
                "sandbox": "cape",
                "report": {"network": {}, "signatures": []},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_cape_network_hosts_not_list(self):
        result = SandboxProcessor.process(
            {
                "sandbox": "cape",
                "report": {"network": {"hosts": "not a list"}, "malscore": 5},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_extremely_large_signature_list(self):
        sigs = [{"name": f"sig_{i}"} for i in range(10000)]
        result = SandboxProcessor.process(
            {
                "sandbox": "triage",
                "report": {"targets": [{"score": 5, "signatures": sigs, "iocs": {}}], "ttp": []},
            }
        )
        assert result is None or isinstance(result, dict)

    def test_deeply_nested_garbage(self):
        """Deeply nested dicts should not cause recursion errors."""
        d = {"sandbox": "triage", "report": {}}
        current = d["report"]
        for i in range(50):
            current["nested"] = {}
            current = current["nested"]
        result = SandboxProcessor.process(d)
        assert result is None or isinstance(result, dict)


# ── Benign Filter Fuzz ───────────────────────────────────────────────────


class TestBenignFilterFuzz:
    """Benign IP/domain filters must not crash on garbage input."""

    def test_empty_string_ip(self):
        # Should not raise
        SandboxProcessor._is_benign_ip("")

    def test_none_ip(self):
        try:
            SandboxProcessor._is_benign_ip(None)
        except (TypeError, AttributeError):
            pass  # Acceptable to raise on None

    def test_ipv6_address(self):
        # Should handle gracefully (not crash)
        result = SandboxProcessor._is_benign_ip("::1")
        assert isinstance(result, bool)

    def test_garbage_string_ip(self):
        result = SandboxProcessor._is_benign_ip("not.an.ip.address.at.all")
        assert isinstance(result, bool)

    def test_empty_string_domain(self):
        SandboxProcessor._is_benign_domain("")

    def test_very_long_domain(self):
        SandboxProcessor._is_benign_domain("a" * 10000 + ".com")
