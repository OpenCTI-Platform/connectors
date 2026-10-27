import json
import re
from unittest.mock import MagicMock

import pytest
from connector.asn_enricher import AsnEnricher
from connector.domain_enricher import DomainEnricher
from connector.ip_enricher import IpEnricher
from connector.stairwell import StairwellClient
from connectors_sdk.exceptions.error import DataRetrievalError


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
    # RPSL lastModified is when the record changed, not when the ASN was
    # registered.
    assert "x_stairwell_registration_date" not in asn
    assert asn["x_stairwell_last_modified"] == "2010-01-15"
    note = next(o for o in payload["objects"] if o["type"] == "note")
    assert "**Last modified:** 2010-01-15" in note["content"]
    assert "Registration" not in note["content"]


def test_untrusted_whois_and_dns_values_are_markdown_escaped():
    from connector.stix_builder import md_code, md_fence, md_text

    whois = "OrgName: Evil\n```\n[click](http://evil.example)\n```"
    org = "Evil [Org](http://evil.example)"
    rdns = "www.evil.example"
    answer = "evil|cell`x"
    first_seen = "2026-01-01 | injected"

    ip_client = _client(
        {
            "get_ip": (
                200,
                {"geoLocation": {"city": "[c](http://e)"}, "asns": [64500]},
            ),
            "get_ip_whois": (
                200,
                {"record": {"whoisString": whois, "arinOrg": {"name": org}}},
            ),
            "get_ip_hostnames": (200, {"hostnames": [rdns]}),
        }
    )
    helper = _helper()
    IpEnricher(helper, ip_client, default_tlp="amber").enrich(
        {
            "id": "x",
            "standard_id": "ipv4-addr--1",
            "entity_type": "IPv4-Addr",
            "value": "203.0.113.5",
        }
    )
    note = next(
        o
        for o in json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
        if o["type"] == "note"
    )["content"]
    assert md_fence(whois.strip()) in note
    assert f"({md_text(org)})" in note
    assert f"- {md_text(rdns)}" in note
    assert md_text("[c](http://e)") in note

    asn_client = _client(
        {
            "get_asn_whois": (
                200,
                {
                    "asn": 64500,
                    "records": [{"whoisString": whois, "arinAsn": {"name": org}}],
                },
            )
        }
    )
    helper = _helper()
    AsnEnricher(helper, asn_client, default_tlp="amber").enrich(
        {
            "id": "x",
            "standard_id": "autonomous-system--1",
            "entity_type": "Autonomous-System",
            "number": 64500,
        }
    )
    note = next(
        o
        for o in json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
        if o["type"] == "note"
    )["content"]
    assert md_fence(whois.strip()) in note
    assert f"**Organization:** {md_text(org)}" in note

    dns_client = _client(
        {
            "get_hostname_metadata_v1": (200, {}),
            "get_hostname_v2": (200, {}),
            "get_hostname_whitelist_status": (200, {}),
            "get_hostname_resolutions": (
                200,
                {
                    "resolutions": [
                        {"recordType": "TXT", "answer": answer, "firstSeen": first_seen}
                    ]
                },
            ),
        }
    )
    helper = _helper()
    DomainEnricher(helper, dns_client, default_tlp="amber").enrich(
        {
            "id": "x",
            "standard_id": "domain-name--1",
            "entity_type": "Domain-Name",
            "value": "evil.example",
        }
    )
    note = next(
        o
        for o in json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
        if o["type"] == "note"
    )["content"]
    row = next(line for line in note.splitlines() if line.startswith("| 1 |"))
    assert md_code(answer, in_table=True) in row
    assert md_text(first_seen) in row
    # Seven unescaped pipes: six columns, none injected by the values.
    assert len(re.findall(r"(?<!\\)\|", row)) == 7


_DOMAIN_OBS = {
    "id": "x",
    "standard_id": "domain-name--1",
    "entity_type": "Domain-Name",
    "value": "evil.example",
}
_IP_OBS = {
    "id": "x",
    "standard_id": "ipv4-addr--1",
    "entity_type": "IPv4-Addr",
    "value": "203.0.113.5",
}


def _domain_client(statuses, res=None):
    names = (
        "get_hostname_metadata_v1",
        "get_hostname_v2",
        "get_hostname_whitelist_status",
        "get_hostname_resolutions",
    )
    responses = {}
    for name, status in zip(names, statuses):
        body = {} if 200 <= status < 300 else None
        if name == "get_hostname_resolutions" and res is not None:
            body = res
        responses[name] = (status, body)
    return _client(responses)


@pytest.mark.parametrize(
    "statuses",
    [(500, 500, 500, 500), (0, 0, 0, 0), (401, 404, 503, 0)],
)
def test_domain_fails_when_no_stairwell_request_succeeds(statuses):
    helper = _helper()
    with pytest.raises(DataRetrievalError):
        DomainEnricher(helper, _domain_client(statuses), "amber").enrich(_DOMAIN_OBS)
    helper.send_stix2_bundle.assert_not_called()


def test_domain_not_found_and_partial_failure_still_handled():
    helper = _helper()
    msg = DomainEnricher(helper, _domain_client((404,) * 4), "amber").enrich(
        _DOMAIN_OBS
    )
    assert "not found" in msg
    helper.send_stix2_bundle.assert_not_called()
    DomainEnricher(helper, _domain_client((500, 200, 500, 500)), "amber").enrich(
        _DOMAIN_OBS
    )
    helper.send_stix2_bundle.assert_called_once()


def test_domain_resolutions_limit_zero_emits_no_resolutions():
    res = {
        "resolutions": [
            {"recordType": "A", "answer": "1.2.3.4"},
            {"recordType": "AAAA", "answer": "2001:db8::1"},
        ]
    }
    helper = _helper()
    DomainEnricher(
        helper, _domain_client((200,) * 4, res), "amber", resolutions_limit=0
    ).enrich(_DOMAIN_OBS)
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    assert not [o for o in objects if o["type"] in ("ipv4-addr", "ipv6-addr")]
    assert not [o for o in objects if o["type"] == "relationship"]
    assert not [o for o in objects if o.get("abstract") == "Stairwell DNS History"]


def test_domain_resolution_answers_must_be_valid_addresses():
    res = {
        "resolutions": [
            {"recordType": "A", "answer": "1.2.3.4:80"},
            {"recordType": "A", "answer": "198.51.100.7"},
            {"recordType": "AAAA", "answer": "198.51.100.8"},
        ]
    }
    helper = _helper()
    DomainEnricher(helper, _domain_client((200,) * 4, res), "amber").enrich(_DOMAIN_OBS)
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    ips = [(o["type"], o["value"]) for o in objects if o["type"].startswith("ipv")]
    assert ips == [("ipv4-addr", "198.51.100.7")]


@pytest.mark.parametrize("statuses", [(500, 500), (0, 401), (503, 0)])
def test_ip_fails_when_neither_ip_nor_whois_request_succeeds(statuses):
    client = _client(
        {
            "get_ip": (statuses[0], None),
            "get_ip_whois": (statuses[1], None),
            "get_ip_hostnames": (500, None),
        }
    )
    helper = _helper()
    with pytest.raises(DataRetrievalError):
        IpEnricher(helper, client, "amber").enrich(_IP_OBS)
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize("status", [500, 401, 0])
def test_asn_fails_when_the_whois_request_fails(status):
    helper = _helper()
    client = _client({"get_asn_whois": (status, None)})
    with pytest.raises(DataRetrievalError):
        AsnEnricher(helper, client, "amber").enrich(
            {
                "id": "x",
                "standard_id": "autonomous-system--1",
                "entity_type": "Autonomous-System",
                "number": 64500,
            }
        )
    helper.send_stix2_bundle.assert_not_called()


def test_identical_intelligence_on_two_ips_gives_two_notes():
    notes = []
    for ip in ("203.0.113.5", "203.0.113.6"):
        client = _client(
            {
                "get_ip": (200, {"geoLocation": {"country": "US"}}),
                "get_ip_whois": (200, {"record": {"arinOrg": {"name": "Same Org"}}}),
                "get_ip_hostnames": (200, {"hostnames": []}),
            }
        )
        helper = _helper()
        IpEnricher(helper, client, "amber").enrich(
            {
                "id": ip,
                "standard_id": f"ipv4-addr--{ip}",
                "entity_type": "IPv4-Addr",
                "value": ip,
            }
        )
        objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
        notes += [o for o in objects if o["type"] == "note"]
    assert len({n["id"] for n in notes}) == 2


@pytest.mark.parametrize(
    "bodies",
    [
        # (status, body) per endpoint: v1, v2, whitelist, resolutions.
        [(200, None)] * 4,
        [(200, None), (500, None), (200, None), (0, None)],
    ],
)
def test_domain_ok_status_without_a_parsed_body_is_not_success(bodies):
    names = (
        "get_hostname_metadata_v1",
        "get_hostname_v2",
        "get_hostname_whitelist_status",
        "get_hostname_resolutions",
    )
    helper = _helper()
    client = _client(dict(zip(names, bodies)))
    with pytest.raises(DataRetrievalError):
        DomainEnricher(helper, client, "amber").enrich(_DOMAIN_OBS)
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "ip, whois",
    [((200, None), (200, None)), ((200, None), (503, None)), ((0, None), (200, None))],
)
def test_ip_ok_status_without_a_parsed_body_is_not_success(ip, whois):
    client = _client(
        {"get_ip": ip, "get_ip_whois": whois, "get_ip_hostnames": (500, None)}
    )
    helper = _helper()
    with pytest.raises(DataRetrievalError):
        IpEnricher(helper, client, "amber").enrich(_IP_OBS)
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "wl, v2, labelled",
    [
        ({"whitelisted": False}, {"whitelisted": True}, False),
        ({"is_whitelisted": False}, {"status": "WHITELISTED"}, False),
        ({}, {"whitelisted": True}, True),
        ({"whitelisted": True}, {"whitelisted": False}, True),
        (None, {"status": "WHITELISTED"}, True),
    ],
)
def test_dedicated_whitelist_answer_takes_precedence(wl, v2, labelled):
    client = _client(
        {
            "get_hostname_metadata_v1": (200, {}),
            "get_hostname_v2": (200, v2),
            "get_hostname_whitelist_status": (200 if wl is not None else 500, wl),
            "get_hostname_resolutions": (200, {"resolutions": []}),
        }
    )
    helper = _helper()
    DomainEnricher(helper, client, "amber").enrich(_DOMAIN_OBS)
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    domain = next(o for o in objects if o["type"] == "domain-name")
    assert ("stairwell:whitelisted" in domain.get("labels", [])) is labelled


def test_dns_answers_become_valid_hostnames_and_never_the_domain_itself():
    own = _DOMAIN_OBS["value"]
    res = {
        "resolutions": [
            {"recordType": "MX", "answer": "10 mx.example.net"},
            {"recordType": "SRV", "answer": "0 5 5060 sip.example.net."},
            {"recordType": "SOA", "answer": "ns1.example.net. host.example.net. 1 2"},
            {"recordType": "NS", "answer": "NS2.Example.net."},
            {"recordType": "MX", "answer": f"10 {own}"},
            {"recordType": "CNAME", "answer": f"{own}."},
            {"recordType": "CNAME", "answer": "not a hostname"},
            {"recordType": "PTR", "answer": "junk other.example.net"},
        ]
    }
    helper = _helper()
    DomainEnricher(helper, _domain_client((200,) * 4, res), "amber").enrich(_DOMAIN_OBS)
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    domains = [o for o in objects if o["type"] == "domain-name"]
    entity_id = _DOMAIN_OBS["standard_id"]
    # The enriched domain appears once, as the enrichment's own object.
    assert [d["id"] for d in domains].count(entity_id) == 1
    own_sco = next(d for d in domains if d["id"] == entity_id)
    assert own_sco["external_references"]
    assert sorted(d["value"] for d in domains if d["id"] != entity_id) == [
        "mx.example.net",
        "ns1.example.net",
        "ns2.example.net",
        "sip.example.net",
    ]
    rels = [o for o in objects if o["type"] == "relationship"]
    assert all(r["source_ref"] != r["target_ref"] for r in rels)
    assert len(rels) == 4
    # Every answer is still listed in the DNS history Note.
    note = next(o for o in objects if o.get("abstract") == "Stairwell DNS History")
    assert "not a hostname" in note["content"]
