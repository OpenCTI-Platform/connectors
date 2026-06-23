"""Tests for network IOC extraction (#43).

Tests cover:
- client_api.fetch_iocs() with VCR cassettes
- converter_to_stix.create_ioc_observables() STIX object creation
- Cap enforcement
- IP filtering (private/multicast)
- Domain extraction from URLs
- NoResultsException handling
"""

import ipaddress
import os

import pytest
import vcr
from polyswarm_enrichment.client_api import ConnectorClient, _is_private_or_noise
from polyswarm_enrichment.converter_to_stix import ConverterToStix

CASSETTE_DIR = os.path.join(os.path.dirname(__file__), "cassettes")
RHADAMANTHYS_HASH = "7c34cccd3f58c144f561493c511a1a96a227cba58d4e1a737c4cd1b3a8a407ff"
DTRACK_HASH = "cde049c032be6f7971c317a2102f88949e714d371c139f6015e1ce10cff90f18"
UNKNOWN_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


# ── Helpers ──────────────────────────────────────────────────────────


class _StubLogger:
    def info(self, msg, *a, **kw):
        pass

    def warning(self, msg, *a, **kw):
        pass

    def error(self, msg, *a, **kw):
        pass

    def debug(self, msg, *a, **kw):
        pass


class StubHelper:
    """Minimal helper stub for tests."""

    def __init__(self):
        self.connector_logger = _StubLogger()

    def log_info(self, msg, *a, **kw):
        pass

    def log_warning(self, msg, *a, **kw):
        pass

    def log_error(self, msg, *a, **kw):
        pass

    def log_debug(self, msg, *a, **kw):
        pass


class StubConfig:
    api_key = "SCRUBBED"
    community = "default"
    polykg_api_url = "http://fake-polykg:8000"


# ── IP Filtering ─────────────────────────────────────────────────────


class TestIPFiltering:
    def test_private_ip_filtered(self):
        assert _is_private_or_noise("192.168.1.1") is True

    def test_loopback_filtered(self):
        assert _is_private_or_noise("127.0.0.1") is True

    def test_multicast_filtered(self):
        assert _is_private_or_noise("224.0.0.1") is True

    def test_link_local_filtered(self):
        assert _is_private_or_noise("169.254.1.1") is True

    def test_public_ip_not_filtered(self):
        assert _is_private_or_noise("8.8.8.8") is False

    def test_invalid_string_not_filtered(self):
        assert _is_private_or_noise("not-an-ip") is False

    def test_ipv6_loopback_filtered(self):
        assert _is_private_or_noise("::1") is True

    def test_ipv6_public_not_filtered(self):
        assert _is_private_or_noise("2607:f8b0:4004:800::200e") is False


# ── fetch_iocs with VCR ──────────────────────────────────────────────


class TestFetchIOCs:
    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_rhadamanthys.yaml")
    def test_rhadamanthys_has_ips(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(RHADAMANTHYS_HASH)
        assert result is not None
        assert len(result["ips"]) > 0

    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_rhadamanthys.yaml")
    def test_rhadamanthys_has_ttps(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(RHADAMANTHYS_HASH)
        assert result is not None
        assert len(result["ttps"]) > 0
        # TTPs should be MITRE format
        for ttp in result["ttps"]:
            assert ttp.startswith("T")

    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_rhadamanthys.yaml")
    def test_rhadamanthys_has_imphash(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(RHADAMANTHYS_HASH)
        assert result is not None
        assert result["imphash"] != ""

    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_rhadamanthys.yaml")
    def test_rhadamanthys_ips_are_public(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(RHADAMANTHYS_HASH)
        assert result is not None
        for ip in result["ips"]:
            addr = ipaddress.ip_address(ip)
            assert not addr.is_private, f"Private IP not filtered: {ip}"
            assert not addr.is_loopback, f"Loopback IP not filtered: {ip}"

    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_dtrack.yaml")
    def test_dtrack_empty_iocs(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(DTRACK_HASH)
        assert result is not None
        assert len(result["ips"]) == 0
        assert result["imphash"] != ""

    @vcr.use_cassette(f"{CASSETTE_DIR}/ioc_unknown.yaml")
    def test_unknown_hash_returns_none(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(UNKNOWN_HASH)
        assert result is None

    def test_empty_hash_returns_none(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs("")
        assert result is None

    def test_none_hash_returns_none(self, polyswarm_client):
        result = polyswarm_client.fetch_iocs(None)
        assert result is None


# ── create_ioc_observables ───────────────────────────────────────────


class TestCreateIOCObservables:
    @pytest.fixture
    def converter(self):
        return ConverterToStix(StubHelper())

    @pytest.fixture
    def sample_ioc_data(self):
        return {
            "ips": ["179.43.142.201", "74.178.76.44", "23.38.111.119"],
            "urls": ["https://evil.com/payload.exe", "https://bad.org/c2"],
            "domains": ["evil.com", "bad.org"],
            "ttps": ["T1071", "T1027"],
            "imphash": "abc123",
        }

    def test_creates_ip_observables(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        ip_obs = [o for o in objects if o["type"] in ("ipv4-addr", "ipv6-addr")]
        assert len(ip_obs) == 3

    def test_creates_domain_observables(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["domain"],
        )
        domain_obs = [o for o in objects if o["type"] == "domain-name"]
        assert len(domain_obs) == 2

    def test_creates_url_observables(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["url"],
        )
        url_obs = [o for o in objects if o["type"] == "url"]
        assert len(url_obs) == 2

    def test_all_types_enabled(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip", "domain", "url"],
        )
        # 3 IPs + 2 domains + 2 URLs = 7 observables, each with a relationship = 14
        obs = [o for o in objects if o["type"] != "relationship"]
        rels = [o for o in objects if o["type"] == "relationship"]
        assert len(obs) == 7
        assert len(rels) == 7

    def test_cap_enforcement(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            max_count=2,
            enabled_types=["ip", "domain", "url"],
        )
        # Cap=2: should get 2 IPs only (IPs are highest priority)
        obs = [o for o in objects if o["type"] != "relationship"]
        assert len(obs) == 2
        assert all(o["type"] == "ipv4-addr" for o in obs)

    def test_cap_spills_to_domains(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            max_count=4,
            enabled_types=["ip", "domain", "url"],
        )
        # Cap=4: 3 IPs + 1 domain
        obs = [o for o in objects if o["type"] != "relationship"]
        assert len(obs) == 4
        ip_count = sum(1 for o in obs if o["type"] == "ipv4-addr")
        domain_count = sum(1 for o in obs if o["type"] == "domain-name")
        assert ip_count == 3
        assert domain_count == 1

    def test_score_applied(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            ioc_score=15,
            enabled_types=["ip"],
        )
        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        for obs in ip_obs:
            assert obs["x_opencti_score"] == 15

    def test_description_applied(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        for obs in ip_obs:
            assert "sandbox analysis" in obs["x_opencti_description"]
            assert "may not be malicious" in obs["x_opencti_description"]

    def test_label_applied(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        for obs in ip_obs:
            assert "polyswarm:sandbox-observed" in obs["x_opencti_labels"]

    def test_relationship_type_communicates_with(self, converter, sample_ioc_data):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        rels = [o for o in objects if o["type"] == "relationship"]
        for rel in rels:
            assert rel["relationship_type"] == "communicates-with"
            assert rel["source_ref"] == "file--test-123"

    def test_deterministic_ids(self, converter, sample_ioc_data):
        objects1 = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        objects2 = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=sample_ioc_data,
            enabled_types=["ip"],
        )
        ids1 = {o["id"] for o in objects1 if o["type"] == "ipv4-addr"}
        ids2 = {o["id"] for o in objects2 if o["type"] == "ipv4-addr"}
        assert ids1 == ids2, "IDs should be deterministic"

    def test_empty_ioc_data(self, converter):
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data={"ips": [], "urls": [], "domains": [], "ttps": []},
        )
        assert objects == []

    def test_private_ips_in_data_filtered(self, converter):
        """Private IPs that somehow got past client filtering should still create valid obs."""
        ioc_data = {
            "ips": ["8.8.8.8", "192.168.1.1"],  # 1 public, 1 private
            "urls": [],
            "domains": [],
            "ttps": [],
        }
        objects = converter.create_ioc_observables(
            observable_id="file--test-123",
            ioc_data=ioc_data,
            enabled_types=["ip"],
        )
        # Both should create observables (filtering is client_api's job)
        ip_obs = [o for o in objects if o["type"] == "ipv4-addr"]
        assert len(ip_obs) == 2


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def polyswarm_client(monkeypatch):
    """Create a ConnectorClient with validation monkey-patched out."""
    monkeypatch.setattr(ConnectorClient, "_validate_api_access", lambda self: None)
    return ConnectorClient(StubHelper(), StubConfig())
