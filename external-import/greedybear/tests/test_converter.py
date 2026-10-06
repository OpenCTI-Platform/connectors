"""Unit tests for the GreedyBear -> STIX conversion logic.

These cover the pure mapping helpers and the dedup-stability guarantees that are
easy to regress (Note id stability, score derivation, date parsing).
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    return ConverterToStix(
        helper=MagicMock(),
        tlp_level="green",
        operator_name="Test Operator",
    )


def test_derive_score_from_probability():
    assert ConverterToStix._derive_score({"recurrence_probability": 0.5}) == 50
    assert ConverterToStix._derive_score({"recurrence_probability": 0.0}) == 1
    assert ConverterToStix._derive_score({"recurrence_probability": 1.0}) == 100


def test_derive_score_from_reputation_fallback():
    assert ConverterToStix._derive_score({"ip_reputation": "known attacker"}) == 80
    assert ConverterToStix._derive_score({"ip_reputation": "mass scanner"}) == 40


def test_derive_score_none_when_no_signal():
    assert ConverterToStix._derive_score({}) is None
    assert ConverterToStix._derive_score({"ip_reputation": "unknown thing"}) is None


def test_parse_dt_formats():
    assert ConverterToStix._parse_dt("2026-06-16") == datetime(
        2026, 6, 16, tzinfo=timezone.utc
    )
    assert ConverterToStix._parse_dt("2026-06-16T10:11:12Z") == datetime(
        2026, 6, 16, 10, 11, 12, tzinfo=timezone.utc
    )
    assert ConverterToStix._parse_dt(None) is None
    assert ConverterToStix._parse_dt("not-a-date") is None


def test_note_id_is_stable_across_runs(converter):
    ioc = {"value": "1.2.3.4", "attack_count": 7}
    note_a = converter.create_ioc_note(
        "1.2.3.4", ioc, "ipv4-addr--11111111-1111-4111-8111-111111111111"
    )
    note_b = converter.create_ioc_note(
        "1.2.3.4", ioc, "ipv4-addr--11111111-1111-4111-8111-111111111111"
    )
    assert note_a.id == note_b.id  # same IoC -> same Note id (upsert, not duplicate)


def test_ioc_produces_observable_and_indicator(converter):
    ioc = {
        "value": "8.8.8.8",
        "first_seen": "2026-06-01",
        "last_seen": "2026-06-10",
        "scanner": True,
        "recurrence_probability": 0.9,
    }
    objs = converter.ioc_to_stix_objects(ioc, create_indicators=True)
    types = {o.type for o in objs}
    assert "ipv4-addr" in types
    assert "indicator" in types


def test_domain_ioc_produces_domain_observable_and_enrichment(converter):
    ioc = {
        "value": "evil.example.com",
        "payload_request": True,
        "attacker_country_code": "US",
        "asn": 64500,
        "recurrence_probability": 0.5,
    }
    objs = converter.ioc_to_stix_objects(ioc, create_indicators=True)
    types = {o.type for o in objs}
    assert "domain-name" in types
    assert "indicator" in types
    assert "location" in types
    assert "autonomous-system" in types
    assert "attack-pattern" in types


def test_ipv6_ioc_produces_ipv6_observable(converter):
    objs = converter.ioc_to_stix_objects(
        {"value": "2001:db8::1", "scanner": True}, create_indicators=True
    )
    assert any(o.type == "ipv6-addr" for o in objs)


def test_value_that_is_neither_ip_nor_domain_is_skipped(converter):
    assert converter.ioc_to_stix_objects({"value": "not a value"}) == []


def test_indicators_disabled_still_emits_attack_pattern(converter):
    objs = converter.ioc_to_stix_objects(
        {"value": "8.8.4.4", "scanner": True}, create_indicators=False
    )
    types = {o.type for o in objs}
    assert "indicator" not in types
    assert "attack-pattern" in types


def test_country_with_invalid_code_is_ignored(converter):
    objs = converter.ioc_to_stix_objects(
        {"value": "8.8.4.4", "attacker_country_code": "USA"}, create_indicators=False
    )
    assert not any(o.type == "location" for o in objs)


def test_asn_entry_valid_and_invalid(converter):
    assert any(
        o.type == "autonomous-system"
        for o in converter.asn_entry_to_stix_objects({"asn": 64500, "as_name": "X"})
    )
    assert converter.asn_entry_to_stix_objects({"as_name": "no-asn"}) == []
    assert converter.asn_entry_to_stix_objects({"asn": "not-an-int"}) == []
