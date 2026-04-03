"""Unit tests for sandbox result merging and deduplication."""

import json
from unittest.mock import MagicMock

import pytest

from tests.test_connector import make_connector

# ── _merge_sandbox_results ──────────────────────────────────────────────────


class TestMergeSandboxResults:
    """Verify multi-provider merge: higher-score wins, failures excluded, metadata tagged."""

    def test_empty_results_returns_none(self):
        c = make_connector()
        merged, best = c._merge_sandbox_results({})
        assert merged is None
        assert best is None

    def test_all_none_returns_none(self):
        c = make_connector()
        merged, best = c._merge_sandbox_results({"cape": None, "triage": None})
        assert merged is None

    def test_single_success_returns_as_is(self):
        c = make_connector()
        result = {"status": "SUCCEEDED", "score": 80, "family": "Emotet"}
        merged, best = c._merge_sandbox_results({"cape": result})
        assert merged == result
        assert best == ("cape", result)

    def test_failed_results_excluded(self):
        c = make_connector()
        failed = {"status": "FAILED", "score": 0}
        success = {"status": "SUCCEEDED", "score": 75, "family": "TrickBot"}
        merged, best = c._merge_sandbox_results({"cape": failed, "triage": success})
        assert merged == success
        assert best == ("triage", success)

    def test_multi_provider_merge_uses_higher_score(self):
        c = make_connector()
        cape = {"status": "SUCCEEDED", "score": 90, "family": "DarkGate", "report": {}}
        triage = {"status": "SUCCEEDED", "score": 60, "family": "Generic", "report": {}}
        merged, best = c._merge_sandbox_results({"cape": cape, "triage": triage})
        assert best[0] == "cape"
        assert merged.get("_merged_from") == ["cape", "triage"]

    def test_merge_prefers_family_from_higher_score(self):
        c = make_connector()
        cape = {
            "status": "SUCCEEDED",
            "score": 50,
            "family": "GenericMal",
            "report": {},
        }
        triage = {"status": "SUCCEEDED", "score": 95, "family": "Emotet", "report": {}}
        merged, _ = c._merge_sandbox_results({"cape": cape, "triage": triage})
        assert merged["family"] == "Emotet"


# ── _merge_report_data ──────────────────────────────────────────────────────


class TestMergeReportData:
    """Verify report-level merge: signatures, TTPs, network, dropped files deduplicated."""

    def test_merges_signatures(self):
        c = make_connector()
        base = {"signatures": [{"name": "sig_a"}]}
        other = {"signatures": [{"name": "sig_b"}]}
        merged = c._merge_report_data(base, other)
        names = [s["name"] for s in merged["signatures"]]
        assert "sig_a" in names
        assert "sig_b" in names

    def test_deduplicates_ttps(self):
        c = make_connector()
        base = {"ttps": ["T1055", "T1082"]}
        other = {"ttps": ["T1082", "T1059"]}
        merged = c._merge_report_data(base, other)
        assert len(merged["ttps"]) == 3
        assert "T1055" in merged["ttps"]
        assert "T1082" in merged["ttps"]
        assert "T1059" in merged["ttps"]

    def test_merges_network_data(self):
        c = make_connector()
        base = {"network": {"dns": [{"query": "a.com"}], "hosts": []}}
        other = {"network": {"dns": [{"query": "b.com"}], "hosts": []}}
        merged = c._merge_report_data(base, other)
        queries = [d["query"] for d in merged["network"]["dns"]]
        assert "a.com" in queries
        assert "b.com" in queries

    def test_merges_dropped_files(self):
        c = make_connector()
        base = {"dropped": [{"name": "a.dll"}]}
        other = {"dropped": [{"name": "b.dll"}]}
        merged = c._merge_report_data(base, other)
        assert len(merged["dropped"]) == 2


# ── _merge_network_data ─────────────────────────────────────────────────────


class TestMergeNetworkData:
    """Verify network-level merge: DNS, hosts, etc. are deduplicated by JSON equality."""

    def test_deduplicates_dns(self):
        c = make_connector()
        entry = {"query": "evil.com", "type": "A"}
        base = {"dns": [entry]}
        other = {"dns": [entry, {"query": "other.com", "type": "A"}]}
        merged = c._merge_network_data(base, other)
        assert len(merged["dns"]) == 2

    def test_deduplicates_hosts(self):
        c = make_connector()
        base = {"hosts": ["192.168.1.1", "10.0.0.1"]}
        other = {"hosts": ["10.0.0.1", "203.0.113.5"]}
        merged = c._merge_network_data(base, other)
        assert len(merged["hosts"]) == 3

    def test_empty_inputs(self):
        c = make_connector()
        merged = c._merge_network_data({}, {})
        assert merged == {}


# ── _extract_sandbox_score ──────────────────────────────────────────────────


class TestExtractSandboxScore:
    """Verify score extraction from three possible nesting depths in sandbox JSON."""

    def test_top_level_score(self):
        c = make_connector()
        assert c._extract_sandbox_score({"score": 85}) == 85

    def test_report_score(self):
        c = make_connector()
        assert c._extract_sandbox_score({"report": {"score": 70}}) == 70

    def test_info_score(self):
        c = make_connector()
        assert c._extract_sandbox_score({"report": {"info": {"score": 55}}}) == 55

    def test_none_returns_zero(self):
        c = make_connector()
        assert c._extract_sandbox_score(None) == 0

    def test_empty_returns_zero(self):
        c = make_connector()
        assert c._extract_sandbox_score({}) == 0
