"""Unit tests for StixBuilder — covers STIX compliance, deterministic IDs, polykg."""

from unittest.mock import MagicMock, patch

import pytest
import requests
from connector.stix_builder import StixBuilder

ENTITY_ID = "artifact--00000000-0000-4000-8000-000000000001"
ENTITY = {
    "type": "artifact",
    "spec_version": "2.1",
    "id": ENTITY_ID,
    "hashes": {"SHA-256": "a" * 64},
}

SCAN_DATA = {
    "score": 85,
    "family": "DTrack",
    "labels": ["backdoor"],
    "operating_systems": ["Windows"],
    "sha256": "a" * 64,
    "sha1": "b" * 40,
    "md5": "c" * 32,
    "hashes": {"MD5": "c" * 32, "SHA-256": "a" * 64},
    "detection_stats": {"malicious": 45, "total": 70},
    "engine_detections": [{"engine": "ClamAV", "family": "Backdoor.DTrack"}],
    "permalink": "https://polyswarm.network/scan/results/test",
    "first_seen": "2024-01-01T00:00:00Z",
    "last_seen": "2024-06-01T00:00:00Z",
    "extended_type": "PE32",
    "mimetype": "application/x-dosexec",
}

SANDBOX_DATA = {
    "provider": "triage",
    "score": 90,
    "family": "DTrack",
    "ttps": ["T1055", "T1082"],
    "labels": ["backdoor"],
    "signatures": ["injects_code"],
    "domains": [{"domain": "evil.c2.io"}],
    "ips": ["203.0.113.1"],
    "c2_candidates": [{"ip": "203.0.113.1", "port": 443, "reason": "C2"}],
    "triage_behavioral_score": 9,
    "triage_static_score": 5,
    "triage_sandbox_score": 8,
    "permalink": "https://polyswarm.network/sandbox/results/test",
}

CONFIG = {
    "create_indicators": True,
    "create_observables": True,
    "min_polyscore": 50,
    "replace_with_lower_score": True,
}


@pytest.fixture
def builder(stub_helper):
    return StixBuilder(
        helper=stub_helper,
        polykg_api_url="http://polykg-test:4141",
        polyswarm_api_key="test-key",
    )


@pytest.fixture
def builder_no_polykg(stub_helper):
    return StixBuilder(helper=stub_helper)


# ── Author ────────────────────────────────────────────────────────────────


class TestAuthor:
    """Verify the PolySwarm identity object is deterministic and always present."""

    def test_author_type(self, builder):
        assert builder.author["type"] == "identity"
        assert "PolySwarm" in builder.author["name"]

    def test_author_id_deterministic(self, stub_helper):
        b1 = StixBuilder(helper=stub_helper)
        b2 = StixBuilder(helper=stub_helper)
        assert b1.author["id"] == b2.author["id"]

    def test_author_always_in_bundle(self, builder):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG
        )
        author_objs = [o for o in objects if o.get("type") == "identity"]
        assert len(author_objs) >= 1


# ── Note ID determinism (#37) ──────────────────────────────────────────────


class TestNoteIdDedup:
    """Verify Note IDs are deterministic (same inputs → same UUID) to prevent duplicates (#37)."""

    def test_same_entity_same_type_same_id(self, builder):
        id1 = builder._note_id("artifact--test", "scan-summary")
        id2 = builder._note_id("artifact--test", "scan-summary")
        assert id1 == id2

    def test_different_types_different_ids(self, builder):
        id_scan = builder._note_id("artifact--test", "scan-summary")
        id_triage = builder._note_id("artifact--test", "sandbox-triage")
        assert id_scan != id_triage

    def test_different_entities_different_ids(self, builder):
        id1 = builder._note_id("artifact--aaa", "scan-summary")
        id2 = builder._note_id("artifact--bbb", "scan-summary")
        assert id1 != id2

    def test_note_ids_start_with_prefix(self, builder):
        assert builder._note_id("artifact--test", "scan-summary").startswith("note--")


# ── polykg ──────────────────────────────────────────────────────────────────


class TestPolyKGProfile:
    """Verify polykg profile fetch, caching, and graceful degradation when polykg is absent."""

    def test_known_family_fetched(self, builder, polykg_mock):
        profile = builder._fetch_polykg_profile("DTrack")
        assert profile is not None
        assert profile["family"] == "DTrack"
        assert "Lazarus" in profile["actors"]

    def test_unknown_family_returns_none(self, builder, polykg_mock):
        assert builder._fetch_polykg_profile("TotallyFake") is None

    def test_empty_family_returns_none(self, builder, polykg_mock):
        assert builder._fetch_polykg_profile("") is None
        assert builder._fetch_polykg_profile(None) is None

    def test_no_polykg_url_returns_none(self, builder_no_polykg):
        assert builder_no_polykg._fetch_polykg_profile("DTrack") is None

    def test_result_cached(self, builder, polykg_mock):
        builder._fetch_polykg_profile("DTrack")
        profile = builder._fetch_polykg_profile("DTrack")
        assert profile is not None

    def test_profile_creates_actors(self, builder, polykg_mock):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG
        )
        actors = [o for o in objects if o.get("type") == "threat-actor"]
        assert any("Lazarus" in a.get("name", "") for a in actors)


# ── Label filtering (#36) ───────────────────────────────────────────────────


class TestLabelFiltering:
    """Verify raw engine names (e.g. 'ClamAV', 'Backdoor.DTrack') are excluded from labels (#36)."""

    def test_no_raw_engine_names_in_labels(self, builder):
        labels = builder._collect_labels(SCAN_DATA, None, None)
        for lbl in labels:
            assert "ClamAV" not in lbl
            assert "Backdoor.DTrack" not in lbl


# ── Malware ──────────────────────────────────────────────────────────────────


class TestMalware:
    """Verify Malware SDO creation: deterministic ID, is_family=True, created_by_ref."""

    def test_malware_created_when_family_known(self, builder):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG
        )
        malware_objs = [o for o in objects if o.get("type") == "malware"]
        assert any(m.get("name") == "DTrack" for m in malware_objs)

    def test_malware_id_deterministic(self, stub_helper):
        b1 = StixBuilder(helper=stub_helper)
        b2 = StixBuilder(helper=stub_helper)
        objs1 = b1.build_bundle(entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG)
        objs2 = b2.build_bundle(entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG)
        id1 = next(o["id"] for o in objs1 if o.get("type") == "malware")
        id2 = next(o["id"] for o in objs2 if o.get("type") == "malware")
        assert id1 == id2

    def test_malware_has_created_by_ref(self, builder):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG
        )
        mal = next(o for o in objects if o.get("type") == "malware")
        assert mal["created_by_ref"] == builder.author_id

    def test_malware_is_family_true(self, builder):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, config=CONFIG
        )
        mal = next(o for o in objects if o.get("type") == "malware")
        assert mal["is_family"] is True


# ── Bundle dedup ─────────────────────────────────────────────────────────────


class TestBundleDedup:
    """Verify the final bundle contains no duplicate STIX IDs."""

    def test_no_duplicate_ids(self, builder):
        objects = builder.build_bundle(
            entity=ENTITY, scan_data=SCAN_DATA, sandbox_data=SANDBOX_DATA, config=CONFIG
        )
        ids = [o.get("id") for o in objects if o.get("id")]
        assert len(ids) == len(
            set(ids)
        ), f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"


# ── replace_with_lower_score (#39) ───────────────────────────────────────────


class TestReplaceWithLowerScore:
    """Verify replace_with_lower_score controls whether a lower PolyScore overwrites an existing higher score (#39)."""

    def test_score_kept_when_existing_higher(self, builder):
        entity_with_score = dict(ENTITY, x_opencti_score=95)
        config_no_replace = dict(CONFIG, replace_with_lower_score=False)
        objects = builder.build_bundle(
            entity=entity_with_score, scan_data=SCAN_DATA, config=config_no_replace
        )
        update = next((o for o in objects if o.get("id") == ENTITY_ID), None)
        assert update is not None
        assert (
            update.get("x_opencti_score") is None or update.get("x_opencti_score") >= 95
        )

    def test_score_updated_when_replace_true(self, builder):
        entity_with_score = dict(ENTITY, x_opencti_score=95)
        config_replace = dict(CONFIG, replace_with_lower_score=True)
        objects = builder.build_bundle(
            entity=entity_with_score, scan_data=SCAN_DATA, config=config_replace
        )
        update = next((o for o in objects if o.get("id") == ENTITY_ID), None)
        assert update is not None
        assert "x_opencti_score" in update


# ── Error notes ──────────────────────────────────────────────────────────────


class TestErrorNotes:
    """Verify error Notes are STIX-compliant and reference the originating entity."""

    def test_error_note_type(self, builder):
        note = builder.create_error_note(ENTITY, "Test Error", "detail", ["Fix it"])
        assert note["type"] == "note"

    def test_error_note_deterministic(self, builder):
        n1 = builder.create_error_note(ENTITY, "API Error", "d1", [])
        n2 = builder.create_error_note(ENTITY, "API Error", "d2", [])
        assert n1["id"] == n2["id"]

    def test_error_note_references_entity(self, builder):
        note = builder.create_error_note(ENTITY, "Cat", "det", [])
        assert ENTITY_ID in note["object_refs"]


# ── AI summary formatting ────────────────────────────────────────────────────


class TestAiSummarySection:
    """Guard the AI summary formatter against the dict-vs-str crash.

    The PolySwarm SDK returns the LLM report already parsed as a dict; the
    formatter used to call .strip() on it and raise AttributeError, crashing
    the whole STIX bundle build. It must accept a dict or a JSON string.
    """

    REPORT = {
        "bottom_line": "Malicious RAT with C2 beacon.",
        "observations": ["process injection", "credential dumping"],
        "recommended_actions": "Isolate the host.",
    }

    def test_accepts_dict_report(self):
        out = StixBuilder._format_ai_summary_section(dict(self.REPORT))
        text = "\n".join(out)
        assert "## AI Summary" in text
        assert "Malicious RAT with C2 beacon." in text
        assert "Isolate the host." in text

    def test_accepts_json_string_report(self):
        import json

        out = StixBuilder._format_ai_summary_section(json.dumps(self.REPORT))
        text = "\n".join(out)
        assert "Malicious RAT with C2 beacon." in text

    def test_empty_inputs_return_no_section(self):
        assert StixBuilder._format_ai_summary_section(None) == []
        assert StixBuilder._format_ai_summary_section("") == []
        assert StixBuilder._format_ai_summary_section({}) == []

    def test_plain_text_string_is_passed_through(self):
        out = StixBuilder._format_ai_summary_section("not json, just prose")
        assert any("not json, just prose" in line for line in out)


# ── Author props ─────────────────────────────────────────────────────────────


class TestAuthorProps:
    """Verify _author_props helper exposes created_by_ref."""

    def test_returns_created_by_ref(self, builder):
        props = builder._author_props()
        assert "created_by_ref" in props
        assert props["created_by_ref"] == builder.author_id


# ── polykg HTTP error paths ───────────────────────────────────────────────────


class TestPolyKGHTTPErrors:
    """Verify graceful degradation on HTTP 401/403 and connection errors."""

    def test_401_response_returns_none(self):
        b = StixBuilder(helper=MagicMock(), polykg_api_url="http://fake-polykg.test")
        resp = MagicMock(status_code=401)
        with patch("requests.get", return_value=resp):
            assert b._fetch_polykg_profile("WannaCry") is None

    def test_403_response_returns_none(self):
        b = StixBuilder(helper=MagicMock(), polykg_api_url="http://fake-polykg.test")
        resp = MagicMock(status_code=403)
        with patch("requests.get", return_value=resp):
            assert b._fetch_polykg_profile("WannaCry") is None

    def test_non_200_response_returns_none(self):
        b = StixBuilder(helper=MagicMock(), polykg_api_url="http://fake-polykg.test")
        resp = MagicMock(status_code=404)
        with patch("requests.get", return_value=resp):
            assert b._fetch_polykg_profile("Unknown") is None

    def test_connection_error_opens_circuit(self):
        b = StixBuilder(helper=MagicMock(), polykg_api_url="http://fake-polykg.test")
        StixBuilder._POLYKG_CIRCUIT_OPEN = False
        with patch("requests.get", side_effect=requests.ConnectionError("timeout")):
            assert b._fetch_polykg_profile("Mirai") is None
        assert StixBuilder._POLYKG_CIRCUIT_OPEN is True
        StixBuilder._POLYKG_CIRCUIT_OPEN = False  # cleanup

    def test_request_exception_returns_none(self):
        b = StixBuilder(helper=MagicMock(), polykg_api_url="http://fake-polykg.test")
        StixBuilder._POLYKG_CIRCUIT_OPEN = False
        with patch("requests.get", side_effect=requests.RequestException("err")):
            assert b._fetch_polykg_profile("Mirai") is None
