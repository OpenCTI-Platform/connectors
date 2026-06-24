"""Tests for ConverterToStix STIX object creation."""

import pytest
from polyswarm_enrichment.client_api import ConnectorClient
from polyswarm_enrichment.converter_to_stix import ConverterToStix


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def profile_loader(stub_helper, stub_config, mock_polykg):
    """ConnectorClient backed by mocked polykg API responses."""
    return ConnectorClient(stub_helper, stub_config)


@pytest.fixture()
def converter(stub_helper, profile_loader):
    return ConverterToStix(stub_helper, profile_loader=profile_loader)


@pytest.fixture()
def converter_no_profiles(stub_helper):
    """Converter without any profile data."""
    return ConverterToStix(stub_helper, profile_loader=None)


@pytest.fixture()
def sample_observable():
    return {
        "id": "file--test-observable-id",
        "hashes": {
            "SHA-256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        },
    }


@pytest.fixture()
def sample_polyswarm_data():
    return {
        "community": "default",
        "confidence": 100,
        "x_opencti_score": 97,
        "x_opencti_labels": ["malware_type:trojan", "PolyUnite:EICAR"],
        "x_opencti_description": "PolySwarm analysis description",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
        "mime_type": "application/octet-stream",
        "file_type": "ASCII text",
        "permalink": "https://polyswarm.network/scan/results/file/test",
        "polyswarm_id": "test-id-123",
        "polyscore": 0.97,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-06-01T00:00:00Z",
        "last_seen_dt": None,
        "poly_unite": ["EICAR"],
        "filenames": ["eicar.com"],
        "detections": {"malicious": 30, "total": 32},
    }


@pytest.fixture()
def dtrack_polyswarm_data():
    """PolySwarm-like result with DTrack family name."""
    return {
        "community": "default",
        "confidence": 100,
        "x_opencti_score": 85,
        "x_opencti_labels": ["malware_type:backdoor", "PolyUnite:DTrack"],
        "x_opencti_description": "DTrack analysis",
        "sha256": "abcd1234" * 8,
        "md5": "deadbeef" * 4,
        "sha1": "a1b2c3d4" * 5,
        "mime_type": "application/x-dosexec",
        "file_type": "PE32",
        "permalink": "https://polyswarm.network/scan/results/file/dtrack",
        "polyswarm_id": "dtrack-id",
        "polyscore": 0.85,
        "first_seen": "2023-06-15T00:00:00Z",
        "last_seen": "2024-05-01T00:00:00Z",
        "last_seen_dt": None,
        "poly_unite": ["DTrack"],
        "filenames": ["dtrack.exe"],
        "detections": {"malicious": 25, "total": 30},
    }


# ---------------------------------------------------------------------------
# Author
# ---------------------------------------------------------------------------
class TestCreateAuthor:
    def test_type_is_identity(self, converter):
        author = converter.author
        assert author["type"] == "identity"

    def test_name(self, converter):
        assert converter.author["name"] == "PolySwarm_Malware_Threat_Intelligence"

    def test_identity_class(self, converter):
        assert converter.author["identity_class"] == "organization"

    def test_has_id(self, converter):
        assert converter.author["id"].startswith("identity--")


# ---------------------------------------------------------------------------
# Indicator
# ---------------------------------------------------------------------------
class TestCreateIndicator:
    def test_indicator_type(self, converter, sample_observable, sample_polyswarm_data):
        ind = converter.create_indicator_from_polyswarm(
            sample_observable, sample_polyswarm_data
        )
        assert ind is not None
        assert ind["type"] == "indicator"

    def test_pattern_contains_hash(
        self, converter, sample_observable, sample_polyswarm_data
    ):
        ind = converter.create_indicator_from_polyswarm(
            sample_observable, sample_polyswarm_data
        )
        assert "SHA256" in ind["pattern"]
        assert sample_polyswarm_data["sha256"] in ind["pattern"]

    def test_valid_from_set(self, converter, sample_observable, sample_polyswarm_data):
        ind = converter.create_indicator_from_polyswarm(
            sample_observable, sample_polyswarm_data
        )
        assert "valid_from" in ind

    def test_score_set(self, converter, sample_observable, sample_polyswarm_data):
        ind = converter.create_indicator_from_polyswarm(
            sample_observable, sample_polyswarm_data
        )
        assert ind["x_opencti_score"] == 97


# ---------------------------------------------------------------------------
# Malware WITH profile (DTrack)
# ---------------------------------------------------------------------------
class TestCreateMalwareWithProfile:
    def test_returns_malware_object(
        self, converter, dtrack_polyswarm_data, profile_loader
    ):
        profile = profile_loader.get_profile("DTrack")
        malware, objs, rels = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        assert malware is not None
        assert malware["type"] == "malware"

    def test_is_family(self, converter, dtrack_polyswarm_data, profile_loader):
        profile = profile_loader.get_profile("DTrack")
        malware, _, _ = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        assert malware["is_family"] is True

    def test_malware_types(self, converter, dtrack_polyswarm_data, profile_loader):
        profile = profile_loader.get_profile("DTrack")
        malware, _, _ = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        assert "malware_types" in malware
        assert "Backdoor" in malware["malware_types"]

    def test_has_related_objects(
        self, converter, dtrack_polyswarm_data, profile_loader
    ):
        profile = profile_loader.get_profile("DTrack")
        _, objs, rels = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        assert len(objs) > 0, "Expected additional STIX objects from profile enrichment"
        assert len(rels) > 0, "Expected relationships from profile enrichment"

    def test_contains_threat_actor(
        self, converter, dtrack_polyswarm_data, profile_loader
    ):
        profile = profile_loader.get_profile("DTrack")
        _, objs, _ = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        actor_objs = [o for o in objs if o["type"] == "threat-actor"]
        assert any("Lazarus" in a["name"] for a in actor_objs)

    def test_contains_locations(self, converter, dtrack_polyswarm_data, profile_loader):
        profile = profile_loader.get_profile("DTrack")
        _, objs, _ = converter.create_malware_from_polyswarm(
            dtrack_polyswarm_data, profile=profile
        )
        location_objs = [o for o in objs if o["type"] == "location"]
        location_names = {loc["name"] for loc in location_objs}
        # DTrack originates from North Korea, targets India among others
        assert "North Korea" in location_names
        assert "India" in location_names


# ---------------------------------------------------------------------------
# Malware WITHOUT profile
# ---------------------------------------------------------------------------
class TestCreateMalwareWithoutProfile:
    def test_basic_malware_created(self, converter_no_profiles, sample_polyswarm_data):
        malware, objs, rels = converter_no_profiles.create_malware_from_polyswarm(
            sample_polyswarm_data, profile=None
        )
        assert malware is not None
        assert malware["type"] == "malware"
        assert malware["name"] == "EICAR"

    def test_no_additional_objects_without_profile(
        self, converter_no_profiles, sample_polyswarm_data
    ):
        _, objs, rels = converter_no_profiles.create_malware_from_polyswarm(
            sample_polyswarm_data, profile=None
        )
        assert len(objs) == 0
        assert len(rels) == 0


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------
class TestCreateLocation:
    def test_location_shape(self, converter):
        loc = converter._create_location("Germany")
        assert loc is not None
        assert loc["type"] == "location"
        assert loc["name"] == "Germany"
        assert loc["x_opencti_location_type"] == "Country"
        assert loc["id"].startswith("location--")

    def test_none_for_empty(self, converter):
        assert converter._create_location("") is None
        assert converter._create_location("Unknown") is None


# ---------------------------------------------------------------------------
# Threat Actor
# ---------------------------------------------------------------------------
class TestCreateThreatActor:
    def test_actor_shape(self, converter):
        actor = converter._create_threat_actor("Lazarus")
        assert actor is not None
        assert actor["type"] == "threat-actor"
        assert actor["name"] == "Lazarus"
        assert "labels" in actor
        assert "threat-actor" in actor["labels"]

    def test_actor_with_aliases(self, converter):
        actor = converter._create_threat_actor(
            "Lazarus", all_actors=["Lazarus", "APT38", "Kimsuky"]
        )
        assert "aliases" in actor
        assert "APT38" in actor["aliases"]
        assert "Kimsuky" in actor["aliases"]
        assert "Lazarus" not in actor["aliases"]

    def test_actor_last_seen(self, converter, profile_loader):
        profile = profile_loader.get_profile("DTrack")
        converter._actor_cache.clear()
        actor = converter._create_threat_actor("Lazarus", profile=profile)
        assert "last_seen" in actor


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------
class TestCreateVulnerability:
    def test_cve_shape(self, converter):
        vuln = converter._create_vulnerability("CVE-2023-27350")
        assert vuln is not None
        assert vuln["type"] == "vulnerability"
        assert vuln["name"] == "CVE-2023-27350"
        assert any(
            ref["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2023-27350"
            for ref in vuln["external_references"]
        )

    def test_rejects_invalid_cve(self, converter):
        assert converter._create_vulnerability("not-a-cve") is None
        assert converter._create_vulnerability("") is None


# ---------------------------------------------------------------------------
# Sector
# ---------------------------------------------------------------------------
class TestCreateSector:
    def test_sector_shape(self, converter):
        sector = converter._create_sector("Financial")
        assert sector is not None
        assert sector["type"] == "identity"
        assert sector["identity_class"] == "class"
        assert sector["name"] == "Financial"

    def test_none_for_empty(self, converter):
        assert converter._create_sector("") is None
        assert converter._create_sector("Unknown") is None


# ---------------------------------------------------------------------------
# Relationship
# ---------------------------------------------------------------------------
class TestRelationship:
    def test_relationship_shape(self, converter):
        src = "malware--12345678-1234-4234-8234-123456789abc"
        tgt = "attack-pattern--87654321-4321-4321-8321-cba987654321"
        rel = converter.create_relationship(
            source_id=src,
            relationship_type="uses",
            target_id=tgt,
            description="test relationship",
        )
        assert rel is not None
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "uses"
        assert rel["source_ref"] == src
        assert rel["target_ref"] == tgt
        assert rel["description"] == "test relationship"


# ---------------------------------------------------------------------------
# Cache deduplication
# ---------------------------------------------------------------------------
class TestCacheDeduplication:
    def test_location_cache(self, converter):
        loc1 = converter._create_location("Germany")
        loc2 = converter._create_location("Germany")
        assert loc1 is loc2, "Same location name should return the cached object"

    def test_actor_cache(self, converter):
        a1 = converter._create_threat_actor("Lazarus")
        a2 = converter._create_threat_actor("Lazarus")
        assert a1 is a2

    def test_vulnerability_cache(self, converter):
        v1 = converter._create_vulnerability("CVE-2023-27350")
        v2 = converter._create_vulnerability("CVE-2023-27350")
        assert v1 is v2
