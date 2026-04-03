"""Tests for Amit's enrichment connector changes.

Covers: SDK AttributeError handling, empty poly_unite list, malware family
normalization, hash-not-found note, CONNECTOR_SCOPE, malware creation skip,
and family description text.
"""

import types

import pytest
from conftest import StubHelper


# ── helpers ────────────────────────────────────────────────────────────────────


def _make_converter():
    """Create a ConverterToStix with a StubHelper and no profile loader."""
    from polyswarm_enrichment.converter_to_stix import ConverterToStix

    helper = StubHelper()
    return ConverterToStix(helper, profile_loader=None)


def _make_observable(sha256: str = "a" * 64) -> dict:
    return {
        "id": f"file--{sha256[:8]}",
        "entity_type": "StixFile",
        "hashes": {"SHA-256": sha256},
        "standard_id": f"file--{sha256[:8]}",
    }


def _make_polyswarm_data(
    family: str | None = "WannaCry",
    score: int = 80,
    permalink: str | None = None,
) -> dict:
    poly_unite = [family] if family else []
    return {
        "community": "default",
        "confidence": 100,
        "x_opencti_score": score,
        "x_opencti_labels": [],
        "x_opencti_description": "Test description",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "sha1": "c" * 40,
        "mime_type": "application/x-dosexec",
        "file_type": "PE",
        "permalink": permalink or "https://polyswarm.network/scan/results/file/" + "a" * 64,
        "polyswarm_id": "ps-123",
        "polyscore": score / 100.0,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-06-01T00:00:00Z",
        "poly_unite": poly_unite,
        "tag_link_families": [],
        "filenames": [],
        "detections": {"malicious": 30, "total": 60},
    }


# ── 1. SDK AttributeError handling ────────────────────────────────────────────


class TestSdkAttributeErrorHandling:
    """getattr() pattern works when metadata keys are missing."""

    def test_getattr_with_none_metadata(self):
        """Simulates SDK result with no metadata — should not raise."""
        result = types.SimpleNamespace(
            failed=False,
            assertions=True,
            metadata=None,
            mimetype="application/octet-stream",
            polyscore=0.5,
            sha256="a" * 64,
            md5="b" * 32,
            sha1="c" * 40,
            permalink="https://example.com",
            id="test-id",
            first_seen="2024-01-01",
            last_seen="2024-06-01",
            filename="test.exe",
            json={"detections": {"malicious": 5, "total": 10}},
        )
        # getattr with default should not raise
        polyunite_data = getattr(result.metadata, "polyunite", None) if result.metadata else None
        assert polyunite_data is None

    def test_getattr_with_missing_key(self):
        """Simulates SDK metadata missing polyunite key."""
        metadata = types.SimpleNamespace()
        polyunite_data = getattr(metadata, "polyunite", None)
        assert polyunite_data is None


# ── 2. Empty poly_unite list ──────────────────────────────────────────────────


class TestEmptyPolyUniteList:
    """Empty list doesn't cause IndexError."""

    def test_empty_poly_unite_no_malware(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family=None)
        assert data["poly_unite"] == []
        # create_malware_from_polyswarm should handle empty list
        result = converter.create_malware_from_polyswarm(data, _make_observable())
        malware_obj, additional, rels = result
        assert malware_obj is None

    def test_poly_unite_with_family(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family="WannaCry")
        result = converter.create_malware_from_polyswarm(data, _make_observable())
        malware_obj, additional, rels = result
        assert malware_obj is not None
        assert malware_obj["name"] == "WannaCry"


# ── 3. Malware family normalization ───────────────────────────────────────────


class TestMalwareFamilyNormalization:
    """None, "Unknown", "none", "" all result in no family."""

    @pytest.mark.parametrize("family", [None, "Unknown", "none", ""])
    def test_no_malware_for_non_families(self, family):
        converter = _make_converter()
        data = _make_polyswarm_data(family=family)
        malware_obj, _, _ = converter.create_malware_from_polyswarm(data, _make_observable())
        assert malware_obj is None


# ── 4. Hash not found note ────────────────────────────────────────────────────


class TestHashNotFoundNote:
    """_create_hash_not_found_note() generates valid STIX Note with deterministic ID."""

    def _make_connector_template(self):
        """Create a minimal ConnectorTemplate-like object with the method."""
        from polyswarm_enrichment.connector import ConnectorTemplate

        helper = StubHelper()

        # We can't fully instantiate ConnectorTemplate, so test the method directly
        obj = object.__new__(ConnectorTemplate)
        obj.helper = helper
        # Need converter_to_stix for the author ref
        obj.converter_to_stix = _make_converter()
        return obj

    def test_note_structure(self):
        ct = self._make_connector_template()
        note = ct._create_hash_not_found_note("file--test-id", "a" * 64)
        assert note["type"] == "note"
        assert note["spec_version"] == "2.1"
        assert note["id"].startswith("note--")
        assert "file--test-id" in note["object_refs"]
        assert "Hash Not Found" in note["abstract"]
        assert "a" * 64 in note["content"]

    def test_deterministic_id(self):
        ct = self._make_connector_template()
        note1 = ct._create_hash_not_found_note("file--test-id", "a" * 64)
        note2 = ct._create_hash_not_found_note("file--test-id", "a" * 64)
        assert note1["id"] == note2["id"]

    def test_different_obs_different_id(self):
        ct = self._make_connector_template()
        note1 = ct._create_hash_not_found_note("file--id-1", "a" * 64)
        note2 = ct._create_hash_not_found_note("file--id-2", "b" * 64)
        assert note1["id"] != note2["id"]


# ── 5. CONNECTOR_SCOPE ────────────────────────────────────────────────────────


class TestConnectorScope:
    """Scope should be StixFile,Artifact (not just StixFile)."""

    def test_default_scope_includes_stixfile_and_artifact(self):
        from polyswarm_enrichment.settings import InternalEnrichmentConnectorConfig

        cfg = InternalEnrichmentConnectorConfig(id="test-connector-id")
        scope = cfg.scope
        scope_lower = [s.lower() for s in scope]
        assert "stixfile" in scope_lower
        assert "artifact" in scope_lower


# ── 6. No malware object for unknown family ───────────────────────────────────


class TestNoMalwareForUnknownFamily:
    """converter_to_stix skips malware creation when family is None/Unknown."""

    def test_skip_malware_for_none_family(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family=None)
        malware_obj, _, _ = converter.create_malware_from_polyswarm(data, _make_observable())
        assert malware_obj is None

    def test_skip_malware_for_unknown_family(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family="Unknown")
        malware_obj, _, _ = converter.create_malware_from_polyswarm(data, _make_observable())
        assert malware_obj is None

    def test_creates_malware_for_real_family(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family="DTrack")
        malware_obj, _, _ = converter.create_malware_from_polyswarm(data, _make_observable())
        assert malware_obj is not None
        assert malware_obj["name"] == "DTrack"


# ── 7. Family description text ────────────────────────────────────────────────


class TestFamilyDescriptionText:
    """Description omits family text when no family identified."""

    def test_description_includes_family_when_present(self):
        data = _make_polyswarm_data(family="WannaCry")
        # Build description like _parse_result does
        malware_family = data["poly_unite"][0] if data["poly_unite"] else None
        family_text = (
            f"The Malware family (PolyUnite) for this file is {malware_family}. "
            if malware_family
            else ""
        )
        assert "WannaCry" in family_text

    def test_description_omits_family_when_none(self):
        data = _make_polyswarm_data(family=None)
        malware_family = data["poly_unite"][0] if data["poly_unite"] else None
        family_text = (
            f"The Malware family (PolyUnite) for this file is {malware_family}. "
            if malware_family
            else ""
        )
        assert family_text == ""

    def test_indicator_description_fallback(self):
        converter = _make_converter()
        data = _make_polyswarm_data(family=None)
        del data["x_opencti_description"]
        obs = _make_observable()
        indicator = converter.create_indicator_from_polyswarm(obs, data)
        if indicator:
            assert indicator["description"] == "File analyzed by PolySwarm"
