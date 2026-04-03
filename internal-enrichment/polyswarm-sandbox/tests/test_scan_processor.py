"""VCR-based tests for ScanProcessor — uses real API data from cassettes."""

import pytest

from connector.scan_processor import ScanProcessor
from polyswarm_api.api import PolyswarmAPI
from tests.conftest import EICAR_SHA256, WANNACRY_SHA256, SAMPLE_SHA256


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
                assert "wannacry" in result["family"].lower() or "wanacry" in result["family"].lower()
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
                assert result["detection_stats"]["malicious"] == api_detections["malicious"]
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
                assert "SSDEEP" in hashes or "TLSH" in hashes, \
                    f"Expected extended hashes, got: {list(hashes.keys())}"
                break
