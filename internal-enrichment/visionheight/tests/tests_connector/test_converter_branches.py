from unittest.mock import MagicMock

import stix2
from connector.converter_to_stix import ConverterToStix
from pycti import STIX_EXT_OCTI_SCO


def _make_ip_entity(value: str = "1.2.3.4") -> dict:
    ip = stix2.IPv4Address(value=value)
    return {"id": ip.id, "type": "IPv4-Addr", "value": value}


def _make_domain_entity(value: str = "evil.com") -> dict:
    domain = stix2.DomainName(value=value)
    return {"id": domain.id, "value": value}


def _score(stix_entity: dict):
    return stix_entity["extensions"][STIX_EXT_OCTI_SCO]["score"]


def _labels(stix_entity: dict):
    return stix_entity["extensions"][STIX_EXT_OCTI_SCO].get("labels", [])


def test_enrich_ip_full_payload_emits_all_object_types():
    """A rich IP payload exercises every enrichment branch in enrich_ip."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    data = {
        "risk": {
            "latest_risk": "HIGH",
            "details": [{"tag": "c2"}, {"tag": "scanner"}, {}],
        },
        "tags": ["botnet"],
        "ip_attributes": {
            "tor_exit_node": True,
            "is_datacenter": True,
            "is_mobile": True,
            "is_satellite": True,
            "icloud_private_relay": True,
        },
        "anonymizer": {
            "is_anonymizer": True,
            "commercial_vpn": {"is_commercial_vpn": True},
        },
        "residential_proxy": {"is_residential_proxy": True},
        "infrastructure": {"asn": 64500, "isp": "Example ISP"},
        "location": {"country_code": "US"},
        "vulnerabilities": {"cve": ["CVE-2021-1234", {"cve": "CVE-2022-5678"}, {}]},
        "whois": {"registrant_name": "Acme", "abuse_email": "abuse@acme.com"},
        "services": {"total": 2, "details": [{"port": 80}, {"port": 443}]},
        "blocklist": {"last_seen": "2026-01-01"},
    }

    new_objects = converter.enrich_ip(ip_entity, data)
    type_names = [type(o).__name__ for o in new_objects]

    assert _score(ip_entity) == 100
    assert "AutonomousSystem" in type_names
    assert "Location" in type_names
    assert type_names.count("Vulnerability") == 2  # the empty {} CVE is skipped
    assert "Note" in type_names
    assert "Indicator" in type_names

    # Contextual boolean flags and threat tags all became labels.
    labels = _labels(ip_entity)
    for expected in [
        "botnet",
        "c2",
        "scanner",
        "tor-exit-node",
        "datacenter",
        "mobile",
        "satellite",
        "icloud-private-relay",
        "anonymizer",
        "commercial-vpn",
        "residential-proxy",
    ]:
        assert expected in labels

    # The AutonomousSystem is attributed to the VisionHeight author.
    asn = next(o for o in new_objects if isinstance(o, stix2.AutonomousSystem))
    assert asn.x_opencti_created_by_ref == converter.author["id"]


def test_enrich_ip_asn_present_country_absent_emits_only_asn():
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    ip_entity = _make_ip_entity()
    data = {
        "risk": {"latest_risk": "SUSPICIOUS"},
        "infrastructure": {"asn": 64501, "isp": "ISP"},
    }

    new_objects = converter.enrich_ip(ip_entity, data)
    type_names = [type(o).__name__ for o in new_objects]

    assert "AutonomousSystem" in type_names
    assert "Location" not in type_names
    assert "Indicator" not in type_names  # score 50 < high-risk threshold


def test_enrich_domain_full_payload_emits_all_object_types():
    """A rich domain payload exercises DNS, cert, WHOIS note and indicator branches."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    domain_entity = _make_domain_entity("evil.com")
    data = {
        "risk": {"score": "HIGH"},
        "tags": ["phishing"],
        "dns": {"a_records": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]},
        "ssl_certs": [
            {
                "cert_fingerprint_sha1": "83ce4638bc618bb0b08e17575c15ac06216e5314",
                "cert_issuer_dn": "/C=US/CN=R12/O=Let's Encrypt",
                "cert_subject_dn": "/CN=evil.com",
                "cert_not_before_timestamp": "2026-01-01T00:00:00Z",
                "cert_not_after_timestamp": "2026-12-31T00:00:00Z",
            },
            {"cert_issuer_dn": "missing-sha1"},  # skipped: no fingerprint
        ],
        "whois": [
            {
                "registrar": "RegCo",
                "created_at": "2020-01-01",
                "expires_at": "2027-01-01",
                "age_in_days": 2000,
                "name_servers": ["ns1.example", "ns2.example"],
            }
        ],
    }

    new_objects = converter.enrich_domain(domain_entity, data)
    type_names = [type(o).__name__ for o in new_objects]

    assert _score(domain_entity) == 100
    assert type_names.count("IPv4Address") == 2
    assert type_names.count("X509Certificate") == 1  # entry without sha1 skipped
    assert "Note" in type_names
    assert "Indicator" in type_names

    cert = next(o for o in new_objects if isinstance(o, stix2.X509Certificate))
    assert cert.x_opencti_created_by_ref == converter.author["id"]


def test_enrich_domain_none_tags_does_not_raise():
    """A payload with an explicit null `tags` must be treated as no tags."""
    converter = ConverterToStix(helper=MagicMock(), tlp_level="clear")
    domain_entity = _make_domain_entity("benign.com")
    data = {"risk": {"score": "UNRATED"}, "tags": None}

    new_objects = converter.enrich_domain(domain_entity, data)

    indicators = [o for o in new_objects if isinstance(o, stix2.Indicator)]
    assert indicators == []
