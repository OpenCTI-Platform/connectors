"""Tests for AttackPatternHandler — TTP mapping and STIX Attack Pattern creation."""

import pytest
from conftest import MOCK_ATTACK_PATTERNS_RESPONSE
from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler


@pytest.fixture()
def handler(stub_helper):
    author_id = "identity--test-author-id"
    return AttackPatternHandler(
        stub_helper, author_id, ttp_data=MOCK_ATTACK_PATTERNS_RESPONSE
    )


# ---------------------------------------------------------------------------
# TTP mapping
# ---------------------------------------------------------------------------
class TestTTPMapping:
    def test_ransomware_maps_to_expected_ttps(self, handler):
        ttps = handler.get_ttps_for_malware_types(["ransomware"])
        assert (
            "T1486" in ttps
        ), "Ransomware should map to T1486 (Data Encrypted for Impact)"
        assert (
            "T1490" in ttps
        ), "Ransomware should map to T1490 (Inhibit System Recovery)"

    def test_unknown_type_returns_empty(self, handler):
        ttps = handler.get_ttps_for_malware_types(["nonexistent_malware_type_xyz"])
        assert ttps == []

    def test_multiple_types(self, handler):
        ttps = handler.get_ttps_for_malware_types(["ransomware", "stealer"])
        # Should include both ransomware and stealer TTPs
        assert "T1486" in ttps  # ransomware
        assert "T1555" in ttps  # stealer


# ---------------------------------------------------------------------------
# Attack pattern creation
# ---------------------------------------------------------------------------
class TestCreateAttackPattern:
    def test_attack_pattern_shape(self, handler):
        ap = handler.create_attack_pattern("T1486")
        assert ap is not None
        assert ap["type"] == "attack-pattern"
        assert ap["x_mitre_id"] == "T1486"
        assert "Data Encrypted for Impact" in ap["name"]

    def test_has_kill_chain_phases(self, handler):
        ap = handler.create_attack_pattern("T1486")
        assert "kill_chain_phases" in ap
        phases = ap["kill_chain_phases"]
        assert len(phases) >= 1
        assert phases[0]["kill_chain_name"] == "mitre-attack"

    def test_has_external_references(self, handler):
        ap = handler.create_attack_pattern("T1486")
        assert "external_references" in ap
        refs = ap["external_references"]
        assert any(r["source_name"] == "mitre-attack" for r in refs)
        assert any("attack.mitre.org" in r["url"] for r in refs)

    def test_sub_technique_url(self, handler):
        ap = handler.create_attack_pattern("T1059.001")
        assert ap is not None
        refs = ap["external_references"]
        urls = [r["url"] for r in refs]
        assert any(
            "T1059/001" in u for u in urls
        ), "Sub-technique URL should use / separator"

    def test_unknown_ttp_returns_none(self, handler):
        ap = handler.create_attack_pattern("T9999")
        assert ap is None, "Unknown TTP should return None"


# ---------------------------------------------------------------------------
# No polykg available — graceful degradation
# ---------------------------------------------------------------------------
class TestNoDataAvailable:
    def test_no_data_without_ttp_data(self, stub_helper):
        """Handler created without ttp_data has no TTP data."""
        handler = AttackPatternHandler(stub_helper, "identity--test")
        assert not handler.has_ttp_data()

    def test_skips_attack_patterns_gracefully(self, stub_helper):
        """Without TTP data, create_attack_patterns_for_malware returns empty."""
        handler = AttackPatternHandler(stub_helper, "identity--test")
        patterns, rels = handler.create_attack_patterns_for_malware(
            malware_types=["ransomware"],
            malware_id="malware--test-id",
            malware_name="TestRansomware",
        )
        assert patterns == []
        assert rels == []


# ---------------------------------------------------------------------------
# Patterns for malware
# ---------------------------------------------------------------------------
class TestCreatePatternsForMalware:
    def test_returns_patterns_and_relationships(self, handler):
        patterns, rels = handler.create_attack_patterns_for_malware(
            malware_types=["ransomware"],
            malware_id="malware--test-id",
            malware_name="TestRansomware",
        )
        assert len(patterns) > 0
        assert len(rels) > 0
        # Each pattern should have a matching relationship
        assert len(rels) == len(patterns)

    def test_relationship_type_is_uses(self, handler):
        _, rels = handler.create_attack_patterns_for_malware(
            malware_types=["ransomware"],
            malware_id="malware--test-id",
            malware_name="TestRansomware",
        )
        for rel in rels:
            assert rel["relationship_type"] == "uses"
            assert rel["source_ref"] == "malware--test-id"

    def test_empty_for_unknown_type(self, handler):
        patterns, rels = handler.create_attack_patterns_for_malware(
            malware_types=["nonexistent_type"],
            malware_id="malware--test-id",
            malware_name="Unknown",
        )
        assert patterns == []
        assert rels == []


# ---------------------------------------------------------------------------
# Cache prevents duplicates
# ---------------------------------------------------------------------------
class TestCachePrevents:
    def test_same_id_returned(self, handler):
        ap1 = handler.create_attack_pattern("T1486")
        ap2 = handler.create_attack_pattern("T1486")
        assert ap1 is ap2, "Cached pattern should be the same object"

    def test_clear_cache(self, handler):
        ap1 = handler.create_attack_pattern("T1486")
        handler.clear_cache()
        ap2 = handler.create_attack_pattern("T1486")
        assert ap1 is not ap2, "After cache clear, a new object should be returned"
        assert ap1["id"] == ap2["id"], "IDs should still be deterministic"
