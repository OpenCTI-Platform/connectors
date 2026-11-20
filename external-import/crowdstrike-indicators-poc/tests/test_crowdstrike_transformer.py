"""Tests for the conversion of CrowdStrike indicators into STIX 2.1."""

import copy
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture, make_actor, make_indicator
from crowdstrike_indicators.entities.models import (
    CrowdStrikeIndicator,
    EnrichedCrowdStrikeIndicator,
)
from crowdstrike_indicators.entities.stix import CrowdStrikeStix2Indicator
from crowdstrike_indicators.transform import (
    step01_create_indicator as transformer_module,
)
from crowdstrike_indicators.transform.step01_create_indicator import (
    CROWDSTRIKE_NAMESPACE,
    NATIVELY_HELD_FIELDS,
    X_EXTRA,
    CreateCrowdStrikeIndicator,
    x_property_name,
)
from stix2.exceptions import InvalidValueError

from shared.errors import ItemConversionError

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
SAMPLE_IDS = [f"{row['type']}-{i}" for i, row in enumerate(SAMPLE_ROWS)]

# STIX ids of the fixture rows: UUIDv5 of the CrowdStrike id in the
# CrowdStrike namespace, pinned as literal values.
EXPECTED_IDS = {
    "hash_sha1_a544af123662c61ae0664b4d41457639d24ed7f1": "indicator--1455db42-6c02-5136-aa8f-149a7c58270c",
    "hash_md5_10c9e2cde0416ca92132df8805841b00": "indicator--aeee2c16-be7d-5381-9209-8b83d5e0566b",
    "url_http://malicious-3.example/path/3?id=fixture": "indicator--e81a6c43-4f11-5627-a821-31e09136fa9b",
    "hash_sha256_8c09b37123eb0d9dcec63788149e576b1614ed481ad002512d0a47a09cbf59fc": "indicator--74fccf7a-599a-5dea-ab4e-d6e06412a8c1",
    "hash_sha1_0cf6a0048ea1c355212b6630ebcd34f463691845": "indicator--30c04d2e-9c02-57d4-b4c8-482aea1cc871",
    "ip_address_192.0.2.6": "indicator--85a216e6-db02-5464-9b94-44a5b22096fe",
    "domain_malicious-7.example": "indicator--f975582d-ec64-5f6c-ac8c-1fdea0f69e0b",
    "domain_malicious-8.example": "indicator--0072b9b1-7486-520a-b29e-200aaac0ab83",
    "domain_malicious-9.example": "indicator--102138ca-08e1-579d-b842-b5d1ed584f3e",
    "domain_malicious-10.example": "indicator--c33286b5-33fb-5aeb-8fbd-2ffe5323e4ed",
    "domain_malicious-11.example": "indicator--bd860d95-48d7-50dc-a047-4e01164704f6",
}

T1 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=UTC)


def record(**fields: Any) -> EnrichedCrowdStrikeIndicator:
    """Build a validated record; ``fields`` override the API fields."""
    raw = make_indicator(1, second=int(T2.timestamp()))
    raw.update(fields)
    return EnrichedCrowdStrikeIndicator.model_validate(raw)


def convert(item: EnrichedCrowdStrikeIndicator) -> CrowdStrikeStix2Indicator:
    return CreateCrowdStrikeIndicator().convert(item)


# Reverse tables, written independently of the transformer's own tables.
TYPE_BY_OBJECT_PATH = {
    "domain-name:value": "domain",
    "url:value": "url",
    "ipv4-addr:value": "ip_address",
    "ipv6-addr:value": "ip_address",
    "file:hashes.MD5": "hash_md5",
    "file:hashes.'SHA-1'": "hash_sha1",
    "file:hashes.'SHA-256'": "hash_sha256",
}
CONFIDENCE_BY_SCORE = {85: "high", 50: "medium", 15: "low"}
KILL_CHAIN_BY_PHASE = {
    "reconnaissance": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "command-and-control": "C2",
    "action-on-objectives": "ActionOnObjectives",
}
NATIVELY_HELD = {"id", "indicator", "type", "last_updated", "published_date", "deleted"}


def rebuild(indicator: CrowdStrikeStix2Indicator) -> EnrichedCrowdStrikeIndicator:
    """Recover the CrowdStrike record from native and ``x_crowdstrike_*`` data."""
    (reference,) = [
        ref for ref in indicator.external_references if ref.source_name == "CrowdStrike"
    ]
    object_path = indicator.pattern[1:].split(" = ", 1)[0]
    data: dict[str, Any] = {
        "id": reference.external_id,
        "indicator": indicator.name,
        "type": TYPE_BY_OBJECT_PATH[object_path],
        "last_updated": indicator.modified,
        "published_date": indicator.created,
        "deleted": bool(indicator.get("revoked")),
    }
    if "confidence" in indicator:
        data["malicious_confidence"] = CONFIDENCE_BY_SCORE[indicator.confidence]
    if "kill_chain_phases" in indicator:
        data["kill_chains"] = [
            KILL_CHAIN_BY_PHASE[phase.phase_name]
            for phase in indicator.kill_chain_phases
        ]
    for name, field in EnrichedCrowdStrikeIndicator.model_fields.items():
        api_name = field.alias or name
        if name not in NATIVELY_HELD and x_property_name(api_name) in indicator:
            data[api_name] = indicator[x_property_name(api_name)]
    data.update(indicator.get(X_EXTRA, {}))
    return EnrichedCrowdStrikeIndicator.model_validate(data)


def comparable(item: CrowdStrikeIndicator) -> dict[str, Any]:
    """JSON form of a record, with the equivalences of the round trip.

    Empty lists read as absent, a missing ``published_date`` as equal to
    ``last_updated``, a missing ``deleted`` as false, and
    ``malicious_confidence`` is compared case-insensitively.
    """
    dumped = item.model_dump(mode="json", by_alias=True, exclude_none=True)
    dumped = {key: value for key, value in dumped.items() if value != []}
    dumped.setdefault("published_date", dumped["last_updated"])
    dumped.setdefault("deleted", False)
    if "malicious_confidence" in dumped:
        dumped["malicious_confidence"] = dumped["malicious_confidence"].lower()
    return dumped


# --- Error -------------------------------------------------------------------


def test_conversion_error_names_the_indicator_and_the_reason():
    error = ItemConversionError("email_address_a@b.example", "unsupported")

    assert str(error) == (
        "Item email_address_a@b.example could not be converted: unsupported"
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

    with pytest.raises(ItemConversionError) as caught:
        convert(item)

    assert caught.value.item_id == "email_address_a@b.example"
    assert "'email_address'" in str(caught.value)


def test_invalid_ip_address_fails():
    with pytest.raises(ItemConversionError, match="not an IP address"):
        convert(record(type="ip_address", indicator="not-an-ip"))


@pytest.mark.parametrize("raw", SAMPLE_ROWS, ids=SAMPLE_IDS)
def test_id_is_derived_from_the_crowdstrike_id(raw):
    result = convert(CrowdStrikeIndicator.model_validate(raw))

    assert result.id == EXPECTED_IDS[raw["id"]]


def test_crowdstrike_namespace_is_pinned():
    assert CROWDSTRIKE_NAMESPACE == uuid.UUID("772e62ec-40d9-5c7b-8696-73937645c55b")
    assert CROWDSTRIKE_NAMESPACE == uuid.uuid5(uuid.NAMESPACE_DNS, "crowdstrike.com")


def test_same_crowdstrike_id_gives_same_id():
    first = convert(record(id="domain_a.example", last_updated=int(T1.timestamp())))
    second = convert(
        record(
            id="domain_a.example",
            malicious_confidence="low",
            published_date=int(T1.timestamp()),
        )
    )

    assert first.id == second.id


def test_different_crowdstrike_ids_give_different_ids():
    first = convert(record(id="domain_a.example"))
    second = convert(record(id="domain_b.example"))

    assert first.id != second.id


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

    with pytest.raises(ItemConversionError, match="is after last_updated"):
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


@pytest.mark.parametrize(
    "fields",
    [{"malicious_confidence": "unverified"}, {"malicious_confidence": "critical"}, {}],
)
def test_no_confidence_when_not_assessed(fields):
    result = convert(record(**fields))

    assert "confidence" not in result
    assert result.get("x_crowdstrike_malicious_confidence") == fields.get(
        "malicious_confidence"
    )


def test_mapped_confidence_is_not_kept_raw():
    result = convert(record(malicious_confidence="medium"))

    assert result.confidence == 50
    assert "x_crowdstrike_malicious_confidence" not in result


def test_every_sample_confidence_level_maps():
    expected = {"high": 85, "medium": 50, "low": 15, "unverified": None}
    for raw in SAMPLE_ROWS:
        result = convert(CrowdStrikeIndicator.model_validate(raw))
        assert result.get("confidence") == expected[raw["malicious_confidence"]]


def test_c2_kill_chain_phase():
    (phase,) = convert(record(kill_chains=["C2"])).kill_chain_phases

    assert phase.kill_chain_name == "lockheed-martin-cyber-kill-chain"
    assert phase.phase_name == "command-and-control"


def test_known_kill_chains_are_not_kept_raw():
    result = convert(record(kill_chains=["Delivery", "C2"]))

    assert [phase.phase_name for phase in result.kill_chain_phases] == [
        "delivery",
        "command-and-control",
    ]
    assert "x_crowdstrike_kill_chains" not in result


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
    item = EnrichedCrowdStrikeIndicator.model_validate(raw)

    assert comparable(rebuild(convert(item))) == comparable(item)


def test_round_trip_survives_json_serialization():
    item = EnrichedCrowdStrikeIndicator.model_validate(SAMPLE_ROWS[0])
    serialized = convert(item).serialize()

    data = json.loads(serialized)
    parsed = CrowdStrikeStix2Indicator(id=data.pop("id"), **data)

    assert comparable(rebuild(parsed)) == comparable(item)


def test_every_model_field_is_held_natively_or_declared():
    declared = set(CrowdStrikeStix2Indicator._properties)
    for name, field in EnrichedCrowdStrikeIndicator.model_fields.items():
        x_name = x_property_name(field.alias or name)
        if name in NATIVELY_HELD_FIELDS:
            assert x_name not in declared, name
        else:
            assert x_name in declared, name


def test_natively_held_fields_are_not_repeated():
    result = convert(
        record(
            published_date=int(T1.timestamp()),
            deleted=False,
            malicious_confidence="high",
            kill_chains=["C2"],
        )
    )

    for name in NATIVELY_HELD_FIELDS | {"malicious_confidence", "kill_chains"}:
        assert x_property_name(name) not in result, name


def test_round_trip_with_the_equivalences():
    item = record(malicious_confidence="HIGH", kill_chains=["C2", "Unknown"])
    assert item.published_date is None and item.deleted is None

    assert comparable(rebuild(convert(item))) == comparable(item)


def test_round_trip_of_a_revoked_ipv6_record():
    item = record(type="ip_address", indicator="2001:db8::1", deleted=True)

    assert comparable(rebuild(convert(item))) == comparable(item)


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
        with pytest.raises(ItemConversionError) as caught:
            convert(record(id="forced-id"))

    assert caught.value.item_id == "forced-id"
    assert caught.value.__cause__ is failure


def test_result_goes_into_a_bundle():
    objects = [convert(CrowdStrikeIndicator.model_validate(raw)) for raw in SAMPLE_ROWS]

    assert len(stix2.Bundle(objects=objects).objects) == len(SAMPLE_ROWS)


# --- Resolved actors ---------------------------------------------------------

SALTY = make_actor(
    "SALTY SPIDER",
    actor_id=1,
    first_activity_date=1700000005,
    known_as="Salty",
    motivations=[{"id": 1001, "slug": "criminal", "value": "Criminal"}],
)
WIZARD = make_actor("WIZARD SPIDER", actor_id=2, foo="bar")


def test_resolved_actors_are_kept_with_their_api_fields():
    result = convert(record(actors=["WIZARDSPIDER"], actor_objects_list=[WIZARD]))

    assert result.x_crowdstrike_actor_objects_list == [WIZARD]
    assert X_EXTRA not in result


def test_actor_dates_are_kept_in_json_form():
    result = convert(record(actors=["SALTYSPIDER"], actor_objects_list=[SALTY]))

    [actor] = result.x_crowdstrike_actor_objects_list
    assert actor["first_activity_date"] == "2023-11-14T22:13:25Z"
    assert actor["motivations"] == SALTY["motivations"]


def test_no_resolved_actor_gives_no_property():
    result = convert(record(actors=["SALTYSPIDER"], actor_objects_list=[]))

    assert "x_crowdstrike_actor_objects_list" not in result
    assert X_EXTRA not in result


def test_round_trip_with_actors():
    item = record(
        actors=["SALTYSPIDER", "WIZARDSPIDER"], actor_objects_list=[SALTY, WIZARD]
    )

    rebuilt = rebuild(convert(item))

    assert rebuilt.actor_objects_list == item.actor_objects_list
    assert comparable(rebuilt) == comparable(item)


def test_round_trip_with_actors_through_json():
    item = record(
        actors=["SALTYSPIDER", "WIZARDSPIDER"], actor_objects_list=[SALTY, WIZARD]
    )
    data = json.loads(convert(item).serialize())
    parsed = CrowdStrikeStix2Indicator(id=data.pop("id"), **data)

    rebuilt = rebuild(parsed)

    assert rebuilt.actor_objects_list == item.actor_objects_list
    assert comparable(rebuilt) == comparable(item)


def test_plain_indicator_record_still_converts():
    plain = CrowdStrikeIndicator.model_validate(make_indicator(1, actors=["X"]))
    item = EnrichedCrowdStrikeIndicator.model_validate(
        plain.model_dump(by_alias=True, exclude_unset=True)
    )

    assert "x_crowdstrike_actor_objects_list" not in convert(item)
