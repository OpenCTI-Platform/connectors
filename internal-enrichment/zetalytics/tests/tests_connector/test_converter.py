"""Tests for zetalytics_dns.converter."""

from unittest.mock import MagicMock

import pytest
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
    assert len(objects) == 1
    assert objects[0]["name"] == "Zetalytics"


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
            {"qname": "example.com", "rrtype": "txt", "value": "v=spf1 include:_spf.example.com ~all"},
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
    response = {
        "results": [
            {"asn": "AS65001", "as_name": "PRIVATE-ASN"}
        ]
    }
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


def test_empty_response_produces_no_objects(converter):
    stix_id = "domain-name--00000000-0000-4000-8000-000000000013"
    assert converter.from_domain_passive_dns("example.com", stix_id, None) == []
    assert converter.from_ip_passive_dns("1.2.3.4", stix_id, None) == []
    assert converter.from_ip_context("1.2.3.4", stix_id, None) == []
    assert converter.from_subdomains("example.com", stix_id, None) == []
    assert converter.from_d8s("example.com", stix_id, None) == []
    assert converter.from_ns_glue("example.com", stix_id, None) == []
