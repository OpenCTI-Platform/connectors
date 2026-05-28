"""Tests for ConnectorClient.query_polyswarm() using VCR cassettes."""

import pytest
from polyswarm_enrichment.client_api import ConnectorClient

# EICAR SHA-256 — universally known, always present in PolySwarm
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Keydoor sample — has Triage sandbox TTPs and rich PolyUnite labels
KEYDOOR_SHA256 = "83a37ac38e86dfcccbf405650ef0ef655e2a4671bf5d8b3c405af18fb37bcb89"

# Hash that should never appear in PolySwarm
UNKNOWN_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


@pytest.fixture()
def client(stub_helper, stub_config):
    return ConnectorClient(stub_helper, stub_config)


# ------------------------------------------------------------------
# Query a known hash (EICAR)
# ------------------------------------------------------------------
class TestQueryKnownHash:
    def test_returns_data(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        assert result["data"] is not None, "Expected enrichment data for EICAR hash"

    def test_sha256_matches(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        data = result["data"]
        assert data["sha256"].lower() == EICAR_SHA256.lower()

    def test_has_score(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        data = result["data"]
        assert "x_opencti_score" in data
        assert isinstance(data["x_opencti_score"], int)
        assert 0 <= data["x_opencti_score"] <= 100

    def test_has_detections(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        data = result["data"]
        assert "detections" in data
        assert "malicious" in data["detections"]
        assert "total" in data["detections"]

    def test_has_poly_unite(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        data = result["data"]
        assert "poly_unite" in data
        assert isinstance(data["poly_unite"], list)


# ------------------------------------------------------------------
# Query a TTP-rich hash (Keydoor — Triage sandbox TTPs present)
# ------------------------------------------------------------------
class TestQueryTTPRichHash:
    def test_returns_data(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        assert result["data"] is not None, "Expected enrichment data for Keydoor hash"

    def test_family_is_keydoor(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        data = result["data"]
        assert "Keydoor" in data["poly_unite"]

    def test_has_malware_type_labels(self, client, vcr_instance):
        """PolyUnite labels should include malware type classifications."""
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        data = result["data"]
        labels = data["x_opencti_labels"]
        # Keydoor is classified as virus, greyware, trojan, spyware
        malware_type_labels = [l for l in labels if l.startswith("malware_type:")]
        assert (
            len(malware_type_labels) > 0
        ), "Should have malware_type labels from PolyUnite"

    def test_high_polyscore(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        data = result["data"]
        assert data["x_opencti_score"] >= 90, "Keydoor should have a high score"


# ------------------------------------------------------------------
# Query an unknown/nonexistent hash
# ------------------------------------------------------------------
class TestQueryUnknownHash:
    def test_returns_no_data(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_unknown_hash.yaml"):
            result = client.query_polyswarm(UNKNOWN_HASH)

        assert result["data"] is None

    def test_errors_contain_no_results(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_unknown_hash.yaml"):
            result = client.query_polyswarm(UNKNOWN_HASH)

        assert len(result["errors"]) > 0
        error_types = [e["error_type"] for e in result["errors"]]
        assert "no_results" in error_types


# ------------------------------------------------------------------
# Result data shape validation
# ------------------------------------------------------------------
EXPECTED_DATA_KEYS = {
    "community",
    "confidence",
    "x_opencti_score",
    "x_opencti_labels",
    "x_opencti_description",
    "sha256",
    "md5",
    "sha1",
    "mime_type",
    "file_type",
    "permalink",
    "polyswarm_id",
    "polyscore",
    "first_seen",
    "last_seen",
    "last_seen_dt",
    "poly_unite",
    "filenames",
    "detections",
}


class TestResultDataShape:
    def test_all_expected_keys_present(self, client, vcr_instance):
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        data = result["data"]
        missing = EXPECTED_DATA_KEYS - set(data.keys())
        assert not missing, f"Missing keys in result data: {missing}"
