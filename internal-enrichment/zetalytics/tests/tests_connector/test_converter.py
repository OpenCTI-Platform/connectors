"""Tests for zetalytics_dns.converter."""

from unittest.mock import MagicMock

import pytest
import stix2
from zetalytics_dns.converter import (
    Converter,
    _extract_results,
    _format_date,
    _is_valid_ipv4,
    _is_valid_ipv6,
    _mx_host,
    _normalise_domain,
    _parse_date,
)

# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Example.COM.", "example.com"),
        ("SUB.DOMAIN.NET.", "sub.domain.net"),
        ("already.clean", "already.clean"),
        ("trailing.dot.", "trailing.dot"),
    ],
)
def test_normalise_domain(value, expected):
    assert _normalise_domain(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.2.3.4", True),
        ("255.255.255.255", True),
        ("::1", False),
        ("not-an-ip", False),
        ("", False),
    ],
)
def test_is_valid_ipv4(value, expected):
    assert _is_valid_ipv4(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("::1", True),
        ("2001:db8::1", True),
        ("1.2.3.4", False),
        ("not-an-ip", False),
    ],
)
def test_is_valid_ipv6(value, expected):
    assert _is_valid_ipv6(value) == expected


@pytest.mark.parametrize(
    "raw, expected_host",
    [
        ("10 mail.example.com", "mail.example.com"),
        ("mail.example.com", "mail.example.com"),
        ("20 alt.mail.example.com.", "alt.mail.example.com."),
    ],
)
def test_mx_host(raw, expected_host):
    assert _mx_host(raw) == expected_host


def test_extract_results_empty_on_none():
    assert _extract_results(None) == []


def test_extract_results_returns_list():
    response = {"results": [{"a": 1}, {"b": 2}], "total": 2}
    assert _extract_results(response) == [{"a": 1}, {"b": 2}]


def test_extract_results_handles_missing_key():
    assert _extract_results({"total": 0}) == []


def test_parse_date_unix_timestamp():
    dt = _parse_date(1609459200)
    assert dt is not None
    assert dt.year == 2021
    assert dt.month == 1


def test_parse_date_iso_string():
    dt = _parse_date("2023-11-10T12:00:00Z")
    assert dt is not None
    assert dt.year == 2023
    assert dt.month == 11


def test_parse_date_date_only():
    dt = _parse_date("2023-11-10")
    assert dt is not None
    assert dt.day == 10


def test_parse_date_none_input():
    assert _parse_date(None) is None


def test_format_date_returns_string():
    result = _format_date(1609459200)
    assert result is not None
    assert "2021" in result


# ---------------------------------------------------------------------------
# Converter class tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_helper():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connector_logger.debug = MagicMock()
    helper.connector_logger.warning = MagicMock()
    return helper


@pytest.fixture
def converter(mock_helper):
    return Converter(helper=mock_helper, confidence=60, marking_tlp="TLP:AMBER")


def test_converter_author_is_created(converter):
    assert converter.author["name"] == "Zetalytics"
    assert converter.author["identity_class"] == "organization"


def test_base_objects_contains_author(converter):
    objects = converter.base_objects()
    assert len(objects) == 2
    assert objects[0]["name"] == "Zetalytics"
    assert objects[1]["definition_type"] == "tlp"


def test_from_domain_passive_dns_a_record(converter):
    response = {
        "results": [
            {
                "qname": "example.com",
                "rrtype": "a",
                "value": "1.2.3.4",
                "first_ts": 1609459200,
                "last_ts": 1640995200,
            }
        ]
    }
    domain_stix_id = "domain-name--00000000-0000-4000-8000-000000000001"
    objects = converter.from_domain_passive_dns("example.com", domain_stix_id, response)

    types = {o["type"] for o in objects}
    assert "ipv4-addr" in types
    assert "relationship" in types

    ip_obj = next(o for o in objects if o["type"] == "ipv4-addr")
    assert ip_obj["value"] == "1.2.3.4"

    rel = next(o for o in objects if o["type"] == "relationship")
    assert rel["relationship_type"] == "resolves-to"
    assert rel["source_ref"] == domain_stix_id
    assert rel["target_ref"] == ip_obj["id"]


def test_from_domain_passive_dns_aaaa_record(converter):
    response = {
        "results": [
            {
                "qname": "example.com",
                "rrtype": "aaaa",
                "value": "2001:db8::1",
            }
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000002"
    objects = converter.from_domain_passive_dns("example.com", stix_id, response)

    types = {o["type"] for o in objects}
    assert "ipv6-addr" in types
    assert "relationship" in types


def test_from_domain_passive_dns_mx_record(converter):
    response = {
        "results": [
            {
                "qname": "example.com",
                "rrtype": "mx",
                "value": "10 mail.example.com",
            }
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000003"
    objects = converter.from_domain_passive_dns("example.com", stix_id, response)

    domain_objs = [o for o in objects if o["type"] == "domain-name"]
    assert any(o["value"] == "mail.example.com" for o in domain_objs)


def test_from_domain_passive_dns_txt_creates_note(converter):
    response = {
        "results": [
            {
                "qname": "example.com",
                "rrtype": "txt",
                "value": "v=spf1 include:_spf.example.com ~all",
            },
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000004"
    objects = converter.from_domain_passive_dns("example.com", stix_id, response)

    note_objs = [o for o in objects if o.get("type") == "note"]
    assert len(note_objs) == 1
    assert "v=spf1" in note_objs[0]["content"]


def test_from_domain_passive_dns_deduplicates_ips(converter):
    response = {
        "results": [
            {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4"},
            {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000005"
    objects = converter.from_domain_passive_dns("example.com", stix_id, response)

    ip_objs = [o for o in objects if o["type"] == "ipv4-addr"]
    assert len(ip_objs) == 1


def test_from_domain_passive_dns_skips_invalid_ip(converter):
    response = {
        "results": [
            {"qname": "example.com", "rrtype": "a", "value": "not-an-ip"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000006"
    objects = converter.from_domain_passive_dns("example.com", stix_id, response)

    ip_objs = [o for o in objects if o["type"] == "ipv4-addr"]
    assert len(ip_objs) == 0


def test_from_ip_passive_dns(converter):
    response = {
        "results": [
            {"qname": "example.com", "rrtype": "a", "value": "1.2.3.4", "first_ts": 0},
            {"qname": "other.com", "rrtype": "a", "value": "1.2.3.4"},
        ]
    }
    ip_stix_id = "ipv4-addr--00000000-0000-4000-8000-000000000007"
    objects = converter.from_ip_passive_dns("1.2.3.4", ip_stix_id, response)

    domain_objs = [o for o in objects if o["type"] == "domain-name"]
    assert len(domain_objs) == 2

    rel_objs = [o for o in objects if o["type"] == "relationship"]
    for rel in rel_objs:
        assert rel["target_ref"] == ip_stix_id
        assert rel["relationship_type"] == "resolves-to"


def test_from_ip_context_creates_asn(converter):
    response = {
        "results": [
            {
                "asn": 12345,
                "as_name": "EXAMPLE-NET",
                "prefix": "1.2.3.0/24",
                "country": "GB",
            }
        ]
    }
    ip_stix_id = "ipv4-addr--00000000-0000-4000-8000-000000000008"
    objects = converter.from_ip_context("1.2.3.4", ip_stix_id, response)

    asn_objs = [o for o in objects if o["type"] == "autonomous-system"]
    assert len(asn_objs) == 1
    assert asn_objs[0]["number"] == 12345
    assert asn_objs[0]["name"] == "EXAMPLE-NET"

    rel_objs = [o for o in objects if o["type"] == "relationship"]
    assert any(r["relationship_type"] == "related-to" for r in rel_objs)


def test_from_ip_context_strips_as_prefix(converter):
    """ASN values prefixed with 'AS' should be parsed to an integer."""
    response = {"results": [{"asn": "AS65001", "as_name": "PRIVATE-ASN"}]}
    ip_stix_id = "ipv4-addr--00000000-0000-4000-8000-000000000009"
    objects = converter.from_ip_context("10.0.0.1", ip_stix_id, response)

    asn_objs = [o for o in objects if o["type"] == "autonomous-system"]
    assert len(asn_objs) == 1
    assert asn_objs[0]["number"] == 65001


def test_from_subdomains(converter):
    response = {
        "results": [
            {"qname": "sub1.example.com", "last_seen": "2023-11-10"},
            {"qname": "sub2.example.com", "last_seen": "2023-10-01"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000010"
    objects = converter.from_subdomains("example.com", stix_id, response)

    domain_objs = [o for o in objects if o["type"] == "domain-name"]
    rel_objs = [o for o in objects if o["type"] == "relationship"]

    assert len(domain_objs) == 2
    assert len(rel_objs) == 2
    for rel in rel_objs:
        assert rel["target_ref"] == stix_id


def test_from_d8s_creates_note(converter):
    response = {
        "results": [
            {
                "registrar": "Example Registrar Inc.",
                "creation_date": "2000-01-01",
                "expiry_date": "2030-01-01",
            }
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000011"
    objects = converter.from_d8s("example.com", stix_id, response)

    note_objs = [o for o in objects if o.get("type") == "note"]
    assert len(note_objs) == 1
    assert "Example Registrar Inc." in note_objs[0]["content"]


def test_from_ns_glue(converter):
    response = {
        "results": [
            {"ns": "ns1.example.com", "ip": "5.6.7.8"},
            {"ns": "ns2.example.com"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000012"
    objects = converter.from_ns_glue("example.com", stix_id, response)

    domain_objs = [o for o in objects if o["type"] == "domain-name"]
    assert any(o["value"] == "ns1.example.com" for o in domain_objs)
    assert any(o["value"] == "ns2.example.com" for o in domain_objs)

    ip_objs = [o for o in objects if o["type"] == "ipv4-addr"]
    assert len(ip_objs) == 1
    assert ip_objs[0]["value"] == "5.6.7.8"


def test_tlp_marking_amber_strict(mock_helper):
    """TLP:AMBER+STRICT isn't a stix2 built-in constant and must be built manually."""
    converter = Converter(
        helper=mock_helper, confidence=60, marking_tlp="TLP:AMBER+STRICT"
    )
    marking = converter._tlp_marking()

    assert marking is not None
    assert marking["x_opencti_definition"] == "TLP:AMBER+STRICT"
    assert [m["id"] for m in converter._object_markings()] == [marking["id"]]


def test_note_id_is_deterministic_regardless_of_creation_time(converter):
    """Two notes with identical content must share the same STIX ID even when
    created at different times, so re-running enrichment doesn't create
    duplicate Notes for unchanged data."""
    note_a = converter._make_note(
        content="same content", object_refs=["domain-name--x"]
    )
    note_b = converter._make_note(
        content="same content", object_refs=["domain-name--x"]
    )

    assert note_a["id"] == note_b["id"]
    # created/modified should still reflect real wall-clock time, just not the ID
    assert note_a["created"] == note_a["modified"]


def test_note_id_differs_for_different_content(converter):
    note_a = converter._make_note(content="content one", object_refs=["domain-name--x"])
    note_b = converter._make_note(content="content two", object_refs=["domain-name--x"])

    assert note_a["id"] != note_b["id"]


def test_domain_id_matches_make_domain_id(converter):
    """domain_id() must reproduce the same STIX ID _make_domain() would generate
    for the same value, so pivots can address a domain without recreating it."""
    domain_obj = converter._make_domain("ns1.example.com")
    assert converter.domain_id("NS1.Example.Com.") == domain_obj["id"]


def test_from_domain_passive_dns_tracks_nameserver_and_mx_domains(converter):
    """Only genuine NS/MX records should be tracked for ns2domain/mx2domain
    pivoting -- not CNAME, PTR, or other domain-name records."""
    response = {
        "results": [
            {"qname": "example.com", "rrtype": "ns", "value": "ns1.example.com"},
            {"qname": "example.com", "rrtype": "cname", "value": "alias.example.com"},
            {"qname": "example.com", "rrtype": "mx", "value": "10 mail.example.com"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000020"
    converter.from_domain_passive_dns("example.com", stix_id, response)

    assert converter.nameserver_domains == {"ns1.example.com"}
    assert converter.mx_domains == {"mail.example.com"}


def test_from_ns_glue_tracks_nameserver_domains(converter):
    response = {"results": [{"ns": "ns1.example.com", "ip": "5.6.7.8"}]}
    stix_id = "domain-name--00000000-0000-4000-8000-000000000021"
    converter.from_ns_glue("example.com", stix_id, response)

    assert "ns1.example.com" in converter.nameserver_domains


def test_tlp_clear_marking_carries_its_own_opencti_definition(mock_helper):
    """TLP:CLEAR shares stix2's legacy TLP_WHITE id by design (OpenCTI kept
    the same node when TLP 2.0 renamed WHITE to CLEAR), but it must carry its
    own x_opencti_definition -- previously the connector emitted the bare
    stix2.TLP_WHITE constant (name='TLP:WHITE', no OpenCTI TLP extension
    fields at all), making it indistinguishable from a real TLP:WHITE marking."""
    clear_converter = Converter(
        helper=mock_helper, confidence=60, marking_tlp="TLP:CLEAR"
    )
    white_converter = Converter(
        helper=mock_helper, confidence=60, marking_tlp="TLP:WHITE"
    )

    clear_marking = clear_converter._tlp_marking()
    white_marking = white_converter._tlp_marking()

    assert clear_marking["id"] == white_marking["id"] == stix2.TLP_WHITE["id"]
    assert clear_marking["x_opencti_definition"] == "TLP:CLEAR"
    assert "x_opencti_definition" not in white_marking


def test_base_objects_includes_custom_marking_definition(mock_helper):
    """Non-standard markings (CLEAR, AMBER+STRICT) aren't ready-made stix2
    constants, so the object itself must ship in the bundle rather than only
    being referenced by id via object_marking_refs."""
    converter = Converter(
        helper=mock_helper, confidence=60, marking_tlp="TLP:AMBER+STRICT"
    )
    objects = converter.base_objects()

    marking_ids = [o["id"] for o in objects if o.get("type") == "marking-definition"]
    assert converter._tlp_marking()["id"] in marking_ids


def test_source_tlp_more_restrictive_than_config_wins(mock_helper):
    """Derived objects must not be published at a looser marking than the
    source observable they were derived from."""
    converter = Converter(
        helper=mock_helper,
        confidence=60,
        marking_tlp="TLP:AMBER",
        source_tlp="TLP:RED",
    )

    assert converter._tlp_marking()["id"] == stix2.TLP_RED["id"]


def test_configured_marking_wins_when_more_restrictive_than_source(mock_helper):
    converter = Converter(
        helper=mock_helper,
        confidence=60,
        marking_tlp="TLP:AMBER",
        source_tlp="TLP:CLEAR",
    )

    assert converter._tlp_marking()["id"] == stix2.TLP_AMBER["id"]


def test_make_location_includes_object_marking_refs(converter):
    location = converter._make_location(
        "London, GB", city="London", region="", country_code="GB"
    )

    assert location["object_marking_refs"] == [
        m["id"] for m in converter._object_markings()
    ]


def test_anchor_object_hostname_uses_custom_observable(converter):
    """Hostname observables aren't STIX 2.1 DomainName objects; re-emitting the
    anchor with the wrong SCO type would mismatch OpenCTI's actual stored type
    for the observable being enriched."""
    existing_id = "hostname--00000000-0000-4000-8000-000000000099"
    anchor = converter.anchor_object("hostname", "host.example.com", existing_id)

    assert anchor["type"] != "domain-name"
    assert anchor["value"] == "host.example.com"
    assert anchor["id"] == existing_id


def test_anchor_object_domain_name_still_uses_domain_name(converter):
    existing_id = "domain-name--00000000-0000-4000-8000-000000000098"
    anchor = converter.anchor_object("domain-name", "example.com", existing_id)

    assert anchor["type"] == "domain-name"


def test_from_ns_glue_still_relates_already_seen_nameserver(converter):
    """A nameserver already discovered earlier in the run (e.g. via passive
    DNS) must not cause the glue relationship to be dropped just because
    _make_domain() returns None for the duplicate."""
    existing = converter._make_domain("ns1.example.com")
    response = {"results": [{"ns": "ns1.example.com", "ip": "5.6.7.8"}]}
    stix_id = "domain-name--00000000-0000-4000-8000-000000000030"

    objects = converter.from_ns_glue("example.com", stix_id, response)

    # The domain object itself shouldn't be recreated (already seen)...
    assert not any(o["type"] == "domain-name" for o in objects)
    # ...but the glue relationship must still be created against its id.
    rel_objs = [o for o in objects if o["type"] == "relationship"]
    assert any(
        r["source_ref"] == stix_id and r["target_ref"] == existing["id"]
        for r in rel_objs
    )
    assert any(r["source_ref"] == existing["id"] for r in rel_objs)


def test_from_subdomains_sets_start_and_stop_time(converter):
    response = {
        "results": [
            {
                "qname": "sub1.example.com",
                "date": "2020-01-01",
                "last_seen": "2023-11-10",
            },
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000031"
    objects = converter.from_subdomains("example.com", stix_id, response)

    rel = next(o for o in objects if o["type"] == "relationship")
    assert rel["start_time"].year == 2020
    assert rel["stop_time"].year == 2023


def test_from_whois_converts_arbitrary_fields(converter):
    """Historical WHOIS records don't follow the domain2d8s field layout, so
    the conversion must not depend on that fixed field list."""
    response = {
        "results": [
            {"date": "2019-05-01", "raw": "Domain Name: EXAMPLE.COM"},
        ]
    }
    stix_id = "domain-name--00000000-0000-4000-8000-000000000032"
    objects = converter.from_whois("example.com", stix_id, response)

    note_objs = [o for o in objects if o.get("type") == "note"]
    assert len(note_objs) == 1
    assert "EXAMPLE.COM" in note_objs[0]["content"]


def test_empty_response_produces_no_objects(converter):
    stix_id = "domain-name--00000000-0000-4000-8000-000000000013"
    assert converter.from_domain_passive_dns("example.com", stix_id, None) == []
    assert converter.from_ip_passive_dns("1.2.3.4", stix_id, None) == []
    assert converter.from_ip_context("1.2.3.4", stix_id, None) == []
    assert converter.from_subdomains("example.com", stix_id, None) == []
    assert converter.from_d8s("example.com", stix_id, None) == []
    assert converter.from_whois("example.com", stix_id, None) == []
    assert converter.from_ns_glue("example.com", stix_id, None) == []
