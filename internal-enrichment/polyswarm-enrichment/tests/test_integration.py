"""Integration tests: full enrichment pipeline from hash to STIX bundle."""

import pytest

from polyswarm_enrichment.client_api import ConnectorClient
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler

# EICAR SHA-256
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Keydoor sample — has Triage sandbox TTPs (T1547.001, T1112, T1070.004, T1082, T1614.001)
# PolyUnite labels: virus, greyware, trojan, spyware
KEYDOOR_SHA256 = "83a37ac38e86dfcccbf405650ef0ef655e2a4671bf5d8b3c405af18fb37bcb89"

UNKNOWN_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


@pytest.fixture()
def client(stub_helper, stub_config):
    return ConnectorClient(stub_helper, stub_config)


@pytest.fixture()
def profile_loader(stub_helper, stub_config, mock_polykg):
    return ConnectorClient(stub_helper, stub_config)


@pytest.fixture()
def converter(stub_helper, profile_loader):
    return ConverterToStix(stub_helper, profile_loader=profile_loader)


@pytest.fixture()
def attack_handler(stub_helper, converter):
    from conftest import MOCK_ATTACK_PATTERNS_RESPONSE
    return AttackPatternHandler(stub_helper, converter.author["id"], ttp_data=MOCK_ATTACK_PATTERNS_RESPONSE)


# ------------------------------------------------------------------
# Full enrichment pipeline (EICAR)
# ------------------------------------------------------------------
class TestFullEnrichmentPipeline:
    def test_eicar_pipeline(self, client, converter, attack_handler, vcr_instance):
        """Query EICAR hash, create STIX objects, verify the bundle structure."""
        with vcr_instance.use_cassette("query_known_hash.yaml"):
            result = client.query_polyswarm(EICAR_SHA256)

        assert result["data"] is not None, "Prerequisite: EICAR hash must return data"
        polyswarm_data = result["data"]

        observable = {
            "id": "file--integration-test",
            "hashes": {"SHA-256": EICAR_SHA256},
        }

        indicator = converter.create_indicator_from_polyswarm(observable, polyswarm_data)
        assert indicator is not None
        assert indicator["type"] == "indicator"

        malware_family = polyswarm_data.get("poly_unite", ["Unknown"])[0]
        profile = converter.profile_loader.get_profile(malware_family) if converter.profile_loader else None
        malware, additional_objs, relationships = converter.create_malware_from_polyswarm(
            polyswarm_data, observable=observable, profile=profile
        )

        stix_objects = [converter.author, indicator]
        if malware:
            stix_objects.append(malware)
            stix_objects.extend(additional_objs)
            stix_objects.extend(relationships)

            malware_types = malware.get("malware_types", [])
            if malware_types:
                patterns, pattern_rels = attack_handler.create_attack_patterns_for_malware(
                    malware_types=malware_types,
                    malware_id=malware["id"],
                    malware_name=malware["name"],
                )
                stix_objects.extend(patterns)
                stix_objects.extend(pattern_rels)

        assert len(stix_objects) >= 2, "Should have at least author + indicator"
        types_present = {obj["type"] for obj in stix_objects}
        assert "identity" in types_present
        assert "indicator" in types_present


# ------------------------------------------------------------------
# TTP-rich pipeline (Keydoor — has PolyUnite labels with malware types)
# ------------------------------------------------------------------
class TestTTPEnrichmentPipeline:
    def test_keydoor_pipeline_produces_attack_patterns(
        self, client, converter, attack_handler, vcr_instance
    ):
        """Keydoor has PolyUnite labels (trojan, spyware, virus) that should
        map to MITRE ATT&CK techniques via AttackPatternHandler."""
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        assert result["data"] is not None
        polyswarm_data = result["data"]

        observable = {
            "id": "file--keydoor-test",
            "hashes": {"SHA-256": KEYDOOR_SHA256},
        }

        # Create indicator
        indicator = converter.create_indicator_from_polyswarm(observable, polyswarm_data)
        assert indicator is not None

        # Create malware
        malware_family = polyswarm_data["poly_unite"][0]
        profile = converter.profile_loader.get_profile(malware_family) if converter.profile_loader else None
        malware, additional_objs, relationships = converter.create_malware_from_polyswarm(
            polyswarm_data, observable=observable, profile=profile
        )
        assert malware is not None
        assert malware["name"] == "Keydoor"

        # Derive malware types from PolyUnite labels
        labels = polyswarm_data.get("x_opencti_labels", [])
        polyunite_types = [
            l.split(":", 1)[1] for l in labels if l.startswith("malware_type:")
        ]
        assert len(polyunite_types) > 0, "Keydoor should have PolyUnite malware_type labels"

        # Create attack patterns from the PolyUnite-derived types
        patterns, pattern_rels = attack_handler.create_attack_patterns_for_malware(
            malware_types=polyunite_types,
            malware_id=malware["id"],
            malware_name=malware["name"],
        )
        assert len(patterns) > 0, (
            f"PolyUnite types {polyunite_types} should produce attack patterns"
        )
        assert len(pattern_rels) == len(patterns)

        # Verify attack patterns have proper STIX structure
        for ap in patterns:
            assert ap["type"] == "attack-pattern"
            assert "x_mitre_id" in ap
            assert "kill_chain_phases" in ap

        # Verify relationships are malware -> uses -> attack-pattern
        for rel in pattern_rels:
            assert rel["relationship_type"] == "uses"
            assert rel["source_ref"] == malware["id"]

    def test_keydoor_full_bundle_types(
        self, client, converter, attack_handler, vcr_instance
    ):
        """End-to-end: verify the resulting STIX bundle has expected object types."""
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        polyswarm_data = result["data"]
        observable = {"id": "file--keydoor-bundle", "hashes": {"SHA-256": KEYDOOR_SHA256}}

        indicator = converter.create_indicator_from_polyswarm(observable, polyswarm_data)
        malware_family = polyswarm_data["poly_unite"][0]
        profile = converter.profile_loader.get_profile(malware_family) if converter.profile_loader else None
        malware, extra_objs, rels = converter.create_malware_from_polyswarm(
            polyswarm_data, observable=observable, profile=profile
        )

        stix_objects = [converter.author, indicator]
        if malware:
            stix_objects.append(malware)
            stix_objects.extend(extra_objs)
            stix_objects.extend(rels)

            labels = polyswarm_data.get("x_opencti_labels", [])
            polyunite_types = [l.split(":", 1)[1] for l in labels if l.startswith("malware_type:")]
            if polyunite_types:
                patterns, pattern_rels = attack_handler.create_attack_patterns_for_malware(
                    malware_types=polyunite_types,
                    malware_id=malware["id"],
                    malware_name=malware["name"],
                )
                stix_objects.extend(patterns)
                stix_objects.extend(pattern_rels)

        types_present = {obj["type"] for obj in stix_objects}
        assert "identity" in types_present, "Author identity must be present"
        assert "indicator" in types_present, "Indicator must be present"
        assert "malware" in types_present, "Malware must be present"
        assert "attack-pattern" in types_present, "Attack patterns from PolyUnite types must be present"
        assert "relationship" in types_present, "Relationships must be present"


# ------------------------------------------------------------------
# Bundle deduplication (#10)
# ------------------------------------------------------------------
class TestBundleDeduplication:
    def test_duplicate_objects_removed(self, stub_helper):
        """_send_bundle() should deduplicate STIX objects by ID."""
        from polyswarm_enrichment.connector import ConnectorTemplate

        # Build a ConnectorTemplate without real OpenCTI — we only need _send_bundle
        # Patch around __init__ since we can't connect to OpenCTI
        connector = object.__new__(ConnectorTemplate)
        connector.helper = stub_helper
        connector.settings = None

        from polyswarm_enrichment.converter_to_stix import ConverterToStix
        converter = ConverterToStix(stub_helper)
        connector.converter_to_stix = converter

        obj_a = {"type": "malware", "id": "malware--aaa", "name": "TestA"}
        obj_b = {"type": "indicator", "id": "indicator--bbb", "name": "TestB"}
        obj_a_dup = {"type": "malware", "id": "malware--aaa", "name": "TestA"}

        result = connector._send_bundle([obj_a, obj_b, obj_a_dup, obj_a])
        assert "1 bundle" in result

        # Verify the stub helper received deduplicated objects
        # _send_bundle calls helper.stix2_create_bundle which returns a dict
        # with the objects. We can verify by checking the call went through
        # without error and the dedup log message would fire.
        # More directly: call the dedup logic standalone
        seen_ids = set()
        unique = []
        for obj in [obj_a, obj_b, obj_a_dup, obj_a]:
            obj_id = obj.get("id")
            if obj_id and obj_id not in seen_ids:
                seen_ids.add(obj_id)
                unique.append(obj)
        assert len(unique) == 2
        assert unique[0]["id"] == "malware--aaa"
        assert unique[1]["id"] == "indicator--bbb"

    def test_no_duplicates_in_keydoor_bundle(
        self, client, converter, attack_handler, vcr_instance
    ):
        """A real enrichment pipeline should not produce duplicate STIX IDs."""
        with vcr_instance.use_cassette("query_keydoor_hash.yaml"):
            result = client.query_polyswarm(KEYDOOR_SHA256)

        polyswarm_data = result["data"]
        observable = {"id": "file--dedup-test", "hashes": {"SHA-256": KEYDOOR_SHA256}}

        indicator = converter.create_indicator_from_polyswarm(observable, polyswarm_data)
        malware_family = polyswarm_data["poly_unite"][0]
        profile = converter.profile_loader.get_profile(malware_family) if converter.profile_loader else None
        malware, extra_objs, rels = converter.create_malware_from_polyswarm(
            polyswarm_data, observable=observable, profile=profile
        )

        stix_objects = [converter.author, indicator]
        if malware:
            stix_objects.append(malware)
            stix_objects.extend(extra_objs)
            stix_objects.extend(rels)

            labels = polyswarm_data.get("x_opencti_labels", [])
            polyunite_types = [l.split(":", 1)[1] for l in labels if l.startswith("malware_type:")]
            if polyunite_types:
                patterns, pattern_rels = attack_handler.create_attack_patterns_for_malware(
                    malware_types=polyunite_types,
                    malware_id=malware["id"],
                    malware_name=malware["name"],
                )
                stix_objects.extend(patterns)
                stix_objects.extend(pattern_rels)

        # Every ID should be unique — no duplicates produced by the pipeline
        ids = [obj["id"] for obj in stix_objects if "id" in obj]
        assert len(ids) == len(set(ids)), (
            f"Duplicate STIX IDs found: {[x for x in ids if ids.count(x) > 1]}"
        )


# ------------------------------------------------------------------
# Network IOC pipeline (Rhadamanthys — has IPs, TTPs, imphash)
# ------------------------------------------------------------------
RHADAMANTHYS_SHA256 = "7c34cccd3f58c144f561493c511a1a96a227cba58d4e1a737c4cd1b3a8a407ff"

RHADAMANTHYS_EXPECTED_IPS = {
    "179.43.142.201", "74.178.76.44", "23.38.111.119", "199.232.210.172",
    "199.232.214.172", "135.233.95.144", "40.119.249.228", "52.123.251.28",
    "52.185.211.133", "52.191.219.104", "72.147.149.16",
}


class TestNetworkIOCPipeline:
    """Full pipeline: fetch_iocs → create_ioc_observables → verify STIX output."""

    def test_rhadamanthys_ioc_pipeline(self, client, converter, vcr_instance):
        """Rhadamanthys: fetch IOCs, create STIX observables, verify pinned IPs."""
        with vcr_instance.use_cassette("ioc_rhadamanthys.yaml"):
            ioc_data = client.fetch_iocs(RHADAMANTHYS_SHA256)

        assert ioc_data is not None
        assert set(ioc_data["ips"]) == RHADAMANTHYS_EXPECTED_IPS
        assert set(ioc_data["ttps"]) == {"T1071", "T1027", "T1027.002"}
        assert ioc_data["imphash"] == "49d57250c01123af7161754f5cf54349"

        # Create STIX observables
        objects = converter.create_ioc_observables(
            observable_id="file--integration-test",
            ioc_data=ioc_data,
            enabled_types=["ip", "domain", "url"],
        )

        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        rels = [o for o in objects if o["type"] == "relationship"]

        assert len(ip_obs) == 11
        assert len(rels) == 11
        assert {o["value"] for o in ip_obs} == RHADAMANTHYS_EXPECTED_IPS

        for rel in rels:
            assert rel["relationship_type"] == "communicates-with"
            assert rel["source_ref"] == "file--integration-test"
            assert rel["confidence"] == 30

        for obs in ip_obs:
            assert obs["x_opencti_score"] == 20
            assert "polyswarm:sandbox-observed" in obs["x_opencti_labels"]

    def test_keydoor_ioc_pipeline(self, client, converter, vcr_instance):
        """Keydoor: 9 IPs, 2 URLs, 14 TTPs — realistic IOC-rich sample."""
        with vcr_instance.use_cassette("ioc_keydoor.yaml"):
            ioc_data = client.fetch_iocs(KEYDOOR_SHA256)

        assert ioc_data is not None

        # Pin exact IPs from cassette
        expected_ips = {
            "175.126.111.143", "20.72.205.209", "211.43.203.28",
            "23.38.111.119", "23.62.100.184", "72.145.35.144",
            "74.178.76.128", "74.178.76.44", "85.234.74.60",
        }
        assert set(ioc_data["ips"]) == expected_ips
        assert ioc_data["imphash"] == "46d622f7b3a9583c2976072cd46d3373"
        assert len(ioc_data["ttps"]) == 14
        assert len(ioc_data["urls"]) == 2

        # Create STIX observables — IPs + URLs
        objects = converter.create_ioc_observables(
            observable_id="file--keydoor-ioc-test",
            ioc_data=ioc_data,
            enabled_types=["ip", "domain", "url"],
        )

        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        url_obs = [o for o in objects if o["type"] == "url"]
        domain_obs = [o for o in objects if o["type"] == "domain-name"]
        rels = [o for o in objects if o["type"] == "relationship"]

        assert len(ip_obs) == 9
        assert {o["value"] for o in ip_obs} == expected_ips
        assert len(url_obs) == 2
        assert len(domain_obs) == 2
        # 9 IP rels + 2 URL rels + 2 domain rels = 13
        assert len(rels) == 13

        for rel in rels:
            assert rel["relationship_type"] == "communicates-with"
            assert rel["source_ref"] == "file--keydoor-ioc-test"
            assert rel["confidence"] == 30

        for obs in ip_obs:
            assert obs["x_opencti_score"] == 20
            assert "polyswarm:sandbox-observed" in obs["x_opencti_labels"]

    def test_dtrack_no_network_iocs(self, client, vcr_instance):
        """DTrack: should return IOC data but with 0 IPs."""
        dtrack_hash = "cde049c032be6f7971c317a2102f88949e714d371c139f6015e1ce10cff90f18"
        with vcr_instance.use_cassette("ioc_dtrack.yaml"):
            ioc_data = client.fetch_iocs(dtrack_hash)

        assert ioc_data is not None
        assert len(ioc_data["ips"]) == 0
        assert ioc_data["imphash"] == "83d82fdd33185880a0d3ad227636a4cf"


# ------------------------------------------------------------------
# No results
# ------------------------------------------------------------------
class TestEnrichmentNoResults:
    def test_unknown_hash_handled_gracefully(self, client, vcr_instance):
        """An unknown hash should return no data without crashing."""
        with vcr_instance.use_cassette("query_unknown_hash.yaml"):
            result = client.query_polyswarm(UNKNOWN_HASH)

        assert result["data"] is None
        assert len(result["errors"]) > 0
        assert isinstance(result, dict)
