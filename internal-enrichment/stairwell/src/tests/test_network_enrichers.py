import json
from unittest.mock import MagicMock

from connector.asn_enricher import AsnEnricher
from connector.domain_enricher import DomainEnricher
from connector.ip_enricher import IpEnricher
from connector.stairwell import StairwellClient


def _client(responses):
    c = StairwellClient.__new__(StairwellClient)
    c._base_url = "https://app.stairwell.com"
    c._timeout = 30
    c._session = None
    for name, value in responses.items():
        setattr(c, name, MagicMock(return_value=value))
    return c


def _helper():
    helper = MagicMock()
    helper.send_stix2_bundle = MagicMock()
    return helper


# ---------------------------------------------------------------------------
# Domain enricher
# ---------------------------------------------------------------------------


def test_domain_enricher_uses_resolutions_endpoint():
    v1 = {}
    v2 = {
        "definition": "Hostname",
        "namespace": "dns",
        "hostname": "evil.example.com",
        "etldPlusOne": "example.com",
        "whitelisted": False,
        "resolutions": [],
    }
    wl = {
        "hostname": "evil.example.com",
        "etldPlusOne": "example.com",
        "whitelisted": False,
    }
    res = {
        "resolutions": [
            {
                "recordType": "A",
                "answer": "1.2.3.4",
                "status": "NOERROR",
                "firstSeen": "2026-01-01T00:00:00Z",
                "lastSeen": "2026-04-01T00:00:00Z",
                "observationCount": 12,
            },
            {
                "recordType": "A",
                "answer": "5.6.7.8",
                "status": "NOERROR",
                "firstSeen": "2026-02-01T00:00:00Z",
                "lastSeen": "2026-03-01T00:00:00Z",
                "observationCount": 4,
            },
            {
                "recordType": "MX",
                "answer": "mx1.example.com",
                "status": "NOERROR",
                "firstSeen": "2026-01-01T00:00:00Z",
                "lastSeen": "2026-04-01T00:00:00Z",
                "observationCount": 2,
            },
        ]
    }
    client = _client(
        {
            "get_hostname_metadata_v1": (200, v1),
            "get_hostname_v2": (200, v2),
            "get_hostname_whitelist_status": (200, wl),
            "get_hostname_resolutions": (200, res),
        }
    )
    helper = _helper()
    enricher = DomainEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--d1",
            "standard_id": "domain-name--d1",
            "entity_type": "Domain-Name",
            "value": "evil.example.com",
        }
    )

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in payload["objects"]]
    assert types.count("domain-name") == 2  # source + MX target
    assert types.count("ipv4-addr") == 2
    assert types.count("relationship") == 3  # 2 resolves-to + 1 related-to
    assert types.count("note") == 1

    domain = next(
        o
        for o in payload["objects"]
        if o["type"] == "domain-name" and o["value"] == "evil.example.com"
    )
    assert domain["x_stairwell_etld_plus_one"] == "example.com"

    note = next(o for o in payload["objects"] if o["type"] == "note")
    assert "By record type" in note["content"]
    assert "A (2)" in note["content"]
    assert "MX (1)" in note["content"]


def test_domain_whitelist_label_from_v2_dedicated():
    client = _client(
        {
            "get_hostname_metadata_v1": (200, {}),
            "get_hostname_v2": (200, {"hostname": "google.com"}),
            "get_hostname_whitelist_status": (
                200,
                {"hostname": "google.com", "whitelisted": True},
            ),
            "get_hostname_resolutions": (200, {"resolutions": []}),
        }
    )
    helper = _helper()
    enricher = DomainEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--d2",
            "standard_id": "domain-name--d2",
            "entity_type": "Domain-Name",
            "value": "google.com",
        }
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    domain = next(
        o
        for o in payload["objects"]
        if o["type"] == "domain-name" and o["value"] == "google.com"
    )
    assert "stairwell:whitelisted" in domain["labels"]


def test_domain_resolutions_capped():
    res = {
        "resolutions": [
            {
                "recordType": "A",
                "answer": f"10.0.0.{i}",
                "firstSeen": f"2026-01-{i:02d}T00:00:00Z",
                "observationCount": i,
            }
            for i in range(1, 11)
        ]
    }
    client = _client(
        {
            "get_hostname_metadata_v1": (200, {}),
            "get_hostname_v2": (200, {"hostname": "many.example.com"}),
            "get_hostname_whitelist_status": (200, {"whitelisted": False}),
            "get_hostname_resolutions": (200, res),
        }
    )
    helper = _helper()
    enricher = DomainEnricher(helper, client, default_tlp="amber", resolutions_limit=3)
    msg = enricher.enrich(
        {
            "id": "stix-cyber-observable--d3",
            "standard_id": "domain-name--d3",
            "entity_type": "Domain-Name",
            "value": "many.example.com",
        }
    )
    assert "resolutions=3/10" in msg
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in payload["objects"]]
    assert types.count("ipv4-addr") == 3  # capped


# ---------------------------------------------------------------------------
# IP enricher — V2 GetIPAddressResponse shape
# ---------------------------------------------------------------------------


def test_ip_enricher_parses_v2_geo_and_asns_array():
    ip_data = {
        "definition": "IPv4Address",
        "ipAddress": "52.0.0.1",
        "geoLocation": {
            "country": "US",
            "countryName": "United States",
            "city": "Ashburn",
            "region": "Virginia",
        },
        "subnetInfo": {"cidr": "52.0.0.0", "prefixLength": 14},
        "asns": [16509],
        "cloudProvider": "AWS",
        "isVpn": False,
        "isDatacenter": True,
    }
    whois_resp = {
        "ipAddress": "52.0.0.1",
        "record": {
            "rir": "ARIN",
            "recordType": "ArinNet",
            "whoisString": "NetRange: 52.0.0.0 - 52.95.255.255\nNetName: AT-88-Z",
            "arinOrg": {"name": "Amazon Technologies Inc."},
        },
    }
    hosts = {
        "hostnames": [{"canonicalHostname": "ec2-52-0-0-1.compute-1.amazonaws.com"}]
    }

    client = _client(
        {
            "get_ip": (200, ip_data),
            "get_ip_whois": (200, whois_resp),
            "get_ip_hostnames": (200, hosts),
        }
    )
    helper = _helper()
    enricher = IpEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--ip1",
            "standard_id": "ipv4-addr--ip1",
            "entity_type": "IPv4-Addr",
            "value": "52.0.0.1",
        }
    )

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    ip_sco = next(o for o in payload["objects"] if o["type"] == "ipv4-addr")
    assert "stairwell:cloud-aws" in ip_sco["labels"]
    assert "stairwell:datacenter" in ip_sco["labels"]
    assert "stairwell:vpn" not in ip_sco.get("labels", [])

    # Geo data correctly nested
    assert ip_sco["x_stairwell_country"] == "US"
    assert ip_sco["x_stairwell_country_name"] == "United States"
    assert ip_sco["x_stairwell_city"] == "Ashburn"
    assert ip_sco["x_stairwell_region"] == "Virginia"

    # ASN as int from array
    assert ip_sco["x_stairwell_asn"] == 16509

    # Subnet
    assert ip_sco["x_stairwell_subnet"] == "52.0.0.0/14"

    # Related ASN with org name pulled from whois.record.arinOrg.name
    asn = next(o for o in payload["objects"] if o["type"] == "autonomous-system")
    assert asn["number"] == 16509
    assert asn["name"] == "Amazon Technologies Inc."

    # Note has formatted whois_string
    note = next(o for o in payload["objects"] if o["type"] == "note")
    assert "NetRange" in note["content"]
    assert "ec2-52-0-0-1.compute-1.amazonaws.com" in note["content"]


def test_ip_enricher_handles_unspecified_cloud_provider():
    ip_data = {
        "ipAddress": "8.8.8.8",
        "geoLocation": {"country": "US"},
        "asns": [15169],
        "cloudProvider": "CLOUD_PROVIDER_UNSPECIFIED",
        "isVpn": False,
        "isDatacenter": False,
    }
    client = _client(
        {
            "get_ip": (200, ip_data),
            "get_ip_whois": (200, {"record": {}}),
            "get_ip_hostnames": (200, {}),
        }
    )
    helper = _helper()
    enricher = IpEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--ip2",
            "standard_id": "ipv4-addr--ip2",
            "entity_type": "IPv4-Addr",
            "value": "8.8.8.8",
        }
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    ip_sco = next(o for o in payload["objects"] if o["type"] == "ipv4-addr")
    assert "x_stairwell_cloud_provider" not in ip_sco
    # No datacenter/vpn labels
    assert all(
        not l.startswith("stairwell:datacenter")
        and not l.startswith("stairwell:vpn")
        and not l.startswith("stairwell:cloud-")
        for l in ip_sco.get("labels", [])
    )


# ---------------------------------------------------------------------------
# ASN enricher — V2 GetASNWhoisResponse shape (records: WhoisRecord[])
# ---------------------------------------------------------------------------


def test_asn_enricher_parses_arin_records_array():
    whois_resp = {
        "asn": 15169,
        "records": [
            {
                "rir": "ARIN",
                "recordType": "ArinAsn",
                "whoisString": "ASNumber: 15169\nASName: GOOGLE",
                "arinAsn": {
                    "name": "GOOGLE",
                    "registrationDate": "2000-03-30",
                    "handle": "AS15169",
                },
            }
        ],
    }
    client = _client({"get_asn_whois": (200, whois_resp)})
    helper = _helper()
    enricher = AsnEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--asn1",
            "standard_id": "autonomous-system--asn1",
            "entity_type": "Autonomous-System",
            "number": 15169,
        }
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    asn_sco = next(o for o in payload["objects"] if o["type"] == "autonomous-system")
    assert asn_sco["name"] == "GOOGLE"
    assert asn_sco["x_stairwell_registration_date"] == "2000-03-30"

    note = next(o for o in payload["objects"] if o["type"] == "note")
    assert "GOOGLE" in note["content"]
    assert "ASNumber: 15169" in note["content"]


def test_asn_enricher_parses_rpsl_records():
    whois_resp = {
        "asn": 8075,
        "records": [
            {
                "rir": "RIPE",
                "recordType": "RpslAutNum",
                "rpslAutNum": {
                    "asName": "MICROSOFT-CORP-MSN-AS-BLOCK",
                    "country": ["US"],
                    "lastModified": "2010-01-15",
                },
            }
        ],
    }
    client = _client({"get_asn_whois": (200, whois_resp)})
    helper = _helper()
    enricher = AsnEnricher(helper, client, default_tlp="amber")
    enricher.enrich(
        {
            "id": "stix-cyber-observable--asn2",
            "standard_id": "autonomous-system--asn2",
            "entity_type": "Autonomous-System",
            "number": 8075,
        }
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    asn = next(o for o in payload["objects"] if o["type"] == "autonomous-system")
    assert asn["name"] == "MICROSOFT-CORP-MSN-AS-BLOCK"
    assert asn["x_stairwell_country"] == "US"
    assert asn["x_stairwell_registration_date"] == "2010-01-15"
