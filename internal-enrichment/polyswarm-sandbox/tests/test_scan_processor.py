"""VCR-based tests for ScanProcessor — uses real API data from cassettes."""

import copy
import json
import os

import pytest
import yaml
from connector.scan_processor import ScanProcessor
from polyswarm_api.api import PolyswarmAPI

from tests.conftest import CASSETTE_DIR, EICAR_SHA256, SAMPLE_SHA256, WANNACRY_SHA256


@pytest.fixture
def api(vcr_instance):
    return PolyswarmAPI(key="SCRUBBED")


class TestScanProcessorEdgeCases:
    """Edge cases that don't need real data."""

    def test_returns_none_for_none(self):
        assert ScanProcessor.process(None) is None

    def test_returns_none_for_empty(self):
        assert ScanProcessor.process({}) is None


class TestScanProcessorEICAR:
    """EICAR scan — universally detected, stable baseline."""

    def test_score_near_100(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["score"] >= 99
                break

    def test_family_is_eicar(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["family"].upper() == "EICAR"
                break

    def test_detection_counts_from_api(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                stats = result["detection_stats"]
                assert stats["malicious"] > 0
                assert stats["total"] > 0
                assert stats["malicious"] <= stats["total"]
                break

    def test_has_permalink(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["permalink"].startswith("https://")
                break

    def test_hashes_from_top_level(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["hashes"]["SHA-256"] == EICAR_SHA256
                assert result["sha256"] == EICAR_SHA256
                assert result["md5"] is not None
                assert result["sha1"] is not None
                break

    def test_labels_include_family(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_eicar.yaml"):
            for r in api.search(EICAR_SHA256):
                result = ScanProcessor.process(r.json)
                assert any("eicar" in l.lower() for l in result["stix_labels"])
                break


class TestScanProcessorWannaCry:
    """WannaCry scan — ransomware with rich detection data."""

    def test_score_near_100(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for r in api.search(WANNACRY_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["score"] >= 99
                break

    def test_family_detected(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for r in api.search(WANNACRY_SHA256):
                result = ScanProcessor.process(r.json)
                assert (
                    "wannacry" in result["family"].lower()
                    or "wanacry" in result["family"].lower()
                )
                break

    def test_has_engine_detections(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for r in api.search(WANNACRY_SHA256):
                result = ScanProcessor.process(r.json)
                assert len(result["engine_detections"]) > 0
                # Each detection should have engine name and family
                for det in result["engine_detections"]:
                    assert det["engine"] is not None
                    assert det["family"] is not None
                break

    def test_detection_counts_match_api(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for r in api.search(WANNACRY_SHA256):
                result = ScanProcessor.process(r.json)
                api_detections = r.json.get("detections", {})
                assert (
                    result["detection_stats"]["malicious"]
                    == api_detections["malicious"]
                )
                assert result["detection_stats"]["total"] == api_detections["total"]
                break

    def test_timestamps_present(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_wannacry.yaml"):
            for r in api.search(WANNACRY_SHA256):
                result = ScanProcessor.process(r.json)
                assert result["first_seen"] is not None
                assert result["last_seen"] is not None
                break


class TestScanProcessorSample:
    """gh0stRAT/Pincav sample — verifies extended hash extraction."""

    def test_extended_hashes(self, api, vcr_instance):
        with vcr_instance.use_cassette("hash_search_sample.yaml"):
            for r in api.search(SAMPLE_SHA256):
                result = ScanProcessor.process(r.json)
                hashes = result["hashes"]
                assert "SHA-256" in hashes
                assert "MD5" in hashes
                # Extended hashes from metadata hash tool
                assert (
                    "SSDEEP" in hashes or "TLSH" in hashes
                ), f"Expected extended hashes, got: {list(hashes.keys())}"
                break


def _recorded_scan_polls(cassette="scan_eicar_poll.yaml"):
    """Scan results as recorded from the API while polling an EICAR scan."""
    with open(os.path.join(CASSETTE_DIR, cassette)) as f:
        interactions = yaml.safe_load(f)["interactions"]
    polls = []
    for interaction in interactions:
        try:
            result = json.loads(interaction["response"]["body"]["string"])["result"]
        except (KeyError, TypeError, ValueError):
            continue
        if isinstance(result, dict):
            polls.append(result)
    return polls


class TestScanProcessorNullFields:
    """The API sends null for detections (and other fields) until it fills them in.

    Recorded in scan_eicar_poll.yaml: every poll before the final one has
    "detections": null, some with engine verdicts already in.
    """

    def test_recording_has_null_detections(self):
        polls = _recorded_scan_polls()
        assert any(p.get("detections") is None and p.get("assertions") for p in polls)

    def test_null_detections_does_not_raise(self):
        for poll in _recorded_scan_polls():
            if poll.get("detections") is None:
                assert ScanProcessor.process(poll) is not None

    def test_null_detections_counts_engine_verdicts(self):
        final = _recorded_scan_polls()[-1]
        assert final["detections"] == {"benign": 0, "malicious": 14, "total": 14}
        nulled = copy.deepcopy(final)
        nulled["detections"] = None
        stats = ScanProcessor.process(nulled)["detection_stats"]
        assert (stats["malicious"], stats["total"]) == (14, 14)

    def test_api_detections_used_when_present(self):
        final = _recorded_scan_polls()[-1]
        stats = ScanProcessor.process(final)["detection_stats"]
        assert (stats["malicious"], stats["total"]) == (14, 14)

    def test_null_polyunite_metadata_does_not_raise(self):
        result = {
            "sha256": EICAR_SHA256,
            "metadata": [
                {"tool": "polyunite", "tool_metadata": None},
                None,
            ],
            "assertions": [
                {
                    "verdict": True,
                    "author_name": "engine",
                    "metadata": None,
                    "engine": None,
                },
                None,
            ],
            "detections": None,
            "polyscore": None,
        }
        processed = ScanProcessor.process(result)
        assert processed["family"] == "Unknown"
        assert processed["labels"] == []
        assert processed["detection_stats"]["malicious"] == 1
        assert processed["engine_detections"][0]["family"] == "Malicious"


# A closed scan window with no engine responses, as returned by the live API for
# EICAR on 2026-11-09 (bounty_state 7, not failed, no assertions, nulls).
NO_VERDICT_SCAN = {
    "sha256": EICAR_SHA256,
    "window_closed": True,
    "failed": False,
    "bounty_state": 7,
    "assertions": [],
    "detections": None,
    "polyscore": None,
    "metadata": [],
}


class TestScanProcessorNoVerdicts:
    """A scan with no engine verdicts must not read as a clean score of 0."""

    def test_no_verdict_scan_is_flagged(self):
        result = ScanProcessor.process(NO_VERDICT_SCAN)
        assert result["has_verdicts"] is False
        assert not any(
            label.startswith("polyscore:") for label in result["stix_labels"]
        )

    def test_recorded_final_scan_has_verdicts(self):
        final = _recorded_scan_polls()[-1]
        assert ScanProcessor.process(final)["has_verdicts"] is True

    def test_verdicts_without_polyscore_count(self):
        scan = copy.deepcopy(NO_VERDICT_SCAN)
        scan["assertions"] = [{"verdict": False, "author_name": "engine"}]
        assert ScanProcessor.process(scan)["has_verdicts"] is True
