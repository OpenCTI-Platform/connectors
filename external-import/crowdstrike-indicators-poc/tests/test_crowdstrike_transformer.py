"""Tests for the conversion of CrowdStrike indicators into STIX 2.1."""

import copy
import json
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture, make_indicator
from crowdstrike_indicators import transformer as transformer_module
from crowdstrike_indicators.errors import IndicatorConversionError
from crowdstrike_indicators.models import CrowdStrikeIndicator
from crowdstrike_indicators.stix import CrowdStrikeStix2Indicator
from crowdstrike_indicators.transformer import (
    X_EXTRA,
    CrowdStrikeIndicatorTransformer,
    x_property_name,
)
from stix2.exceptions import InvalidValueError

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]

# Ids computed with pycti 7.261109.0 ``Indicator.generate_id(pattern)`` for the
# fixture rows, with patterns built independently of this code.
PYCTI_IDS = {
    "hash_sha1_a544af123662c61ae0664b4d41457639d24ed7f1": "indicator--3b63cbaa-b145-553c-9697-9e4c98a93d0d",
    "hash_md5_10c9e2cde0416ca92132df8805841b00": "indicator--aa7fc987-2694-5fb9-a23b-220dd368b6df",
    "url_http://malicious-3.example/path/3?id=fixture": "indicator--7b4cc0b4-9099-5018-8c0e-d67242926c67",
    "hash_sha256_8c09b37123eb0d9dcec63788149e576b1614ed481ad002512d0a47a09cbf59fc": "indicator--ac086b97-99f6-5898-a65a-c49e8b0cea0b",
    "hash_sha1_0cf6a0048ea1c355212b6630ebcd34f463691845": "indicator--20441abc-b908-52c6-876b-9866b5795c11",
    "ip_address_192.0.2.6": "indicator--819f620b-8ebf-5a9f-9087-6cee559f72dc",
    "domain_malicious-7.example": "indicator--c9ca11dc-e430-58eb-bf35-b82ffeeea04d",
    "domain_malicious-8.example": "indicator--49f7bafd-95a2-5ed2-9b4f-5b605e1696aa",
    "domain_malicious-9.example": "indicator--15da8078-d116-5c72-a54a-63f2af631731",
    "domain_malicious-10.example": "indicator--42cd3b95-0e73-5421-b1bf-c350d75047f9",
    "domain_malicious-11.example": "indicator--b979e4f4-2874-5607-9213-3efbded6e1ba",
}

T1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)


def record(**fields: Any) -> CrowdStrikeIndicator:
    """Build a validated record; ``fields`` override the API fields."""
    raw = make_indicator(1, second=int(T2.timestamp()))
    raw.update(fields)
    return CrowdStrikeIndicator.model_validate(raw)


def convert(item: CrowdStrikeIndicator) -> CrowdStrikeStix2Indicator:
    return CrowdStrikeIndicatorTransformer().convert(item)


def rebuild(indicator: CrowdStrikeStix2Indicator) -> CrowdStrikeIndicator:
    """Rebuild the CrowdStrike record from the ``x_crowdstrike_*`` properties."""
    data: dict[str, Any] = {}
    for name, field in CrowdStrikeIndicator.model_fields.items():
        api_name = field.alias or name
        if x_property_name(api_name) in indicator:
            data[api_name] = indicator[x_property_name(api_name)]
    data.update(indicator.get(X_EXTRA, {}))
    return CrowdStrikeIndicator.model_validate(data)


def comparable(item: CrowdStrikeIndicator) -> dict[str, Any]:
    """JSON form of a record where empty lists read as absent."""
    dumped = item.model_dump(mode="json", by_alias=True, exclude_none=True)
    return {key: value for key, value in dumped.items() if value != []}


# --- Error -------------------------------------------------------------------


def test_conversion_error_names_the_indicator_and_the_reason():
    error = IndicatorConversionError("email_address_a@b.example", "unsupported")

    assert str(error) == (
        "Indicator email_address_a@b.example could not be converted: unsupported"
    )


# --- Pattern and id ----------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "value", "pattern"),
    [
        (
            "domain",
            "malicious-1.example",
            "[domain-name:value = 'malicious-1.example']",
        ),
        ("url", "http://a.example/p?q=1", "[url:value = 'http://a.example/p?q=1']"),
        ("ip_address", "192.0.2.1", "[ipv4-addr:value = '192.0.2.1']"),
        ("ip_address", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        ("hash_md5", "a" * 32, f"[file:hashes.MD5 = '{'a' * 32}']"),
        ("hash_sha1", "b" * 40, f"[file:hashes.'SHA-1' = '{'b' * 40}']"),
        ("hash_sha256", "c" * 64, f"[file:hashes.'SHA-256' = '{'c' * 64}']"),
    ],
)
def test_pattern_per_type(kind, value, pattern):
    result = convert(record(type=kind, indicator=value))

    assert result.pattern == pattern
    assert result.pattern_type == "stix"


def test_quote_and_backslash_are_escaped():
    result = convert(record(type="url", indicator="http://a.example/it's\\x"))

    assert result.pattern == r"[url:value = 'http://a.example/it\'s\\x']"


def test_unsupported_type_fails_naming_id_and_type():
    item = record(id="email_address_a@b.example", type="email_address")

    with pytest.raises(IndicatorConversionError) as caught:
        convert(item)

    assert caught.value.indicator_id == "email_address_a@b.example"
    assert "'email_address'" in str(caught.value)


def test_invalid_ip_address_fails():
    with pytest.raises(IndicatorConversionError, match="not an IP address"):
        convert(record(type="ip_address", indicator="not-an-ip"))


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_id_matches_pycti(raw):
    result = convert(CrowdStrikeIndicator.model_validate(raw))

    assert result.id == PYCTI_IDS[raw["id"]]


def test_same_value_gives_same_id():
    first = convert(record(id="a", last_updated=int(T1.timestamp())))
    second = convert(record(id="b", malicious_confidence="low"))

    assert first.id == second.id


# --- Native properties -------------------------------------------------------


def test_name_and_dates_of_a_published_record():
    result = convert(
        record(
            indicator="malicious-1.example",
            published_date=int(T1.timestamp()),
            last_updated=int(T2.timestamp()),
        )
    )

    assert result.name == "malicious-1.example"
    assert result.valid_from == result.created == T1
    assert result.modified == T2


def test_dates_without_published_date_fall_back_to_last_updated():
    result = convert(record(last_updated=int(T2.timestamp())))

    assert result.valid_from == result.created == result.modified == T2


def test_published_after_last_update_fails():
    item = record(
        id="late", published_date=int(T2.timestamp()), last_updated=int(T1.timestamp())
    )

    with pytest.raises(IndicatorConversionError, match="is after last_updated"):
        convert(item)


def test_deleted_record_is_revoked():
    assert convert(record(deleted=True)).revoked is True


@pytest.mark.parametrize("fields", [{"deleted": False}, {}])
def test_live_record_has_no_revoked_property(fields):
    result = convert(record(**fields))

    # stix2 holds its default False in memory but never serializes it.
    assert result.revoked is False
    assert "revoked" not in json.loads(result.serialize())


@pytest.mark.parametrize(
    ("level", "confidence"),
    [("high", 85), ("medium", 50), ("low", 15), ("HIGH", 85)],
)
def test_confidence_on_the_stix_scale(level, confidence):
    assert convert(record(malicious_confidence=level)).confidence == confidence


@pytest.mark.parametrize("fields", [{"malicious_confidence": "unverified"}, {}])
def test_no_confidence_when_not_assessed(fields):
    result = convert(record(**fields))

    assert "confidence" not in result
    assert result.get("x_crowdstrike_malicious_confidence") == fields.get(
        "malicious_confidence"
    )


def test_every_sample_confidence_level_maps():
    expected = {"high": 85, "medium": 50, "low": 15, "unverified": None}
    for raw in SAMPLE_ROWS:
        result = convert(CrowdStrikeIndicator.model_validate(raw))
        assert result.get("confidence") == expected[raw["malicious_confidence"]]


def test_c2_kill_chain_phase():
    (phase,) = convert(record(kill_chains=["C2"])).kill_chain_phases

    assert phase.kill_chain_name == "lockheed-martin-cyber-kill-chain"
    assert phase.phase_name == "command-and-control"


def test_every_sample_kill_chain_maps():
    expected = {
        "Reconnaissance": "reconnaissance",
        "Weaponization": "weaponization",
        "Delivery": "delivery",
        "Exploitation": "exploitation",
        "Installation": "installation",
        "C2": "command-and-control",
        "ActionOnObjectives": "action-on-objectives",
    }
    seen = set()
    for raw in SAMPLE_ROWS:
        result = convert(CrowdStrikeIndicator.model_validate(raw))
        phases = [phase.phase_name for phase in result.get("kill_chain_phases", [])]
        assert phases == [expected[kill_chain] for kill_chain in raw["kill_chains"]]
        seen.update(raw["kill_chains"])
    assert seen == set(expected)


def test_unknown_kill_chain_is_skipped_but_kept_raw():
    result = convert(record(kill_chains=["C2", "Unknown"]))

    assert [phase.phase_name for phase in result.kill_chain_phases] == [
        "command-and-control"
    ]
    assert result.x_crowdstrike_kill_chains == ["C2", "Unknown"]


def test_labels_are_copied_verbatim_in_order():
    names = ["KillChain/ActionOnObjectives", "MaliciousConfidence/High", "CSD/X"]

    result = convert(record(labels=[{"name": name} for name in names]))

    assert result.labels == names


def test_no_labels_property_without_labels():
    assert "labels" not in convert(record(labels=[]))


def test_crowdstrike_reference():
    (reference,) = convert(record(id="domain_malicious-1.example")).external_references

    assert reference.source_name == "CrowdStrike"
    assert reference.external_id == "domain_malicious-1.example"


# --- Every source field is kept ----------------------------------------------


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_sample_row_round_trips(raw):
    item = CrowdStrikeIndicator.model_validate(raw)

    assert comparable(rebuild(convert(item))) == comparable(item)


def test_round_trip_survives_json_serialization():
    item = CrowdStrikeIndicator.model_validate(SAMPLE_ROWS[0])
    serialized = convert(item).serialize()

    data = json.loads(serialized)
    parsed = CrowdStrikeStix2Indicator(id=data.pop("id"), **data)

    assert comparable(rebuild(parsed)) == comparable(item)


def test_every_model_field_has_a_declared_x_property():
    declared = set(CrowdStrikeStix2Indicator._properties)
    for name, field in CrowdStrikeIndicator.model_fields.items():
        assert x_property_name(field.alias or name) in declared, name


def test_marker_loses_its_leading_underscore():
    item = record()

    assert convert(item).x_crowdstrike_marker == item.marker


def test_undeclared_field_lands_in_extra():
    result = convert(record(scope=["s1"]))

    assert result[X_EXTRA] == {"scope": ["s1"]}


def test_no_extra_property_without_undeclared_field():
    assert X_EXTRA not in convert(record())


def test_label_dates_are_kept():
    label = {
        "name": "KillChain/C2",
        "created_on": T1.timestamp(),
        "last_valid_on": T2.timestamp(),
    }

    (kept,) = convert(record(labels=[label])).x_crowdstrike_labels

    assert kept == {
        "name": "KillChain/C2",
        "created_on": "2026-11-01T10:00:00Z",
        "last_valid_on": "2026-11-02T10:00:00Z",
    }


def test_empty_list_gives_an_absent_property():
    result = convert(record(actors=[], malware_families=["ExampleFamily1"]))

    assert "x_crowdstrike_actors" not in result
    assert result.x_crowdstrike_malware_families == ["ExampleFamily1"]


def test_input_is_left_unchanged():
    item = CrowdStrikeIndicator.model_validate(SAMPLE_ROWS[0])
    before = copy.deepcopy(item)

    convert(item)

    assert item == before


def test_stix2_failure_is_wrapped_with_its_cause():
    failure = InvalidValueError(CrowdStrikeStix2Indicator, "pattern", "forced")
    with mock.patch.object(
        transformer_module, "CrowdStrikeStix2Indicator", side_effect=failure
    ):
        with pytest.raises(IndicatorConversionError) as caught:
            convert(record(id="forced-id"))

    assert caught.value.indicator_id == "forced-id"
    assert caught.value.__cause__ is failure


def test_result_goes_into_a_bundle():
    objects = [convert(CrowdStrikeIndicator.model_validate(raw)) for raw in SAMPLE_ROWS]

    assert len(stix2.Bundle(objects=objects).objects) == len(SAMPLE_ROWS)
