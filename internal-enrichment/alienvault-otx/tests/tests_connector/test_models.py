import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from otx_client import OtxGeneral, OtxPulse, OtxPulseInfo
from pydantic import ValidationError

RESOURCES = Path(__file__).parent.parent / "resources"


def _load(name: str) -> dict[str, Any]:
    return json.loads((RESOURCES / name).read_text(encoding="utf-8"))


def test_general_should_parse_a_known_ipv4():
    # Given the OTX answer for an IPv4 address that belongs to pulses
    response = _load("general_ipv4_known.json")

    # When validating it
    general = OtxGeneral.model_validate(response)

    # Then the geolocation and the pulses are typed
    assert general.indicator == "192.0.2.10"
    assert general.type == "IPv4"
    assert general.reputation == 0
    assert general.city is None
    assert general.region is None
    assert general.country_name == "Netherlands"
    assert general.pulse_info.count == 2
    assert [pulse.name for pulse in general.pulse_info.pulses] == [
        "Example Scanner Campaign",
        "Example Intrusion Set Activity",
    ]


def test_general_should_parse_an_unknown_ipv4():
    # Given the OTX answer for an IPv4 address without pulse and without geolocation
    response = _load("general_ipv4_unknown.json")

    # When validating it
    general = OtxGeneral.model_validate(response)

    # Then it has no pulse and no geolocation
    assert general.pulse_info.count == 0
    assert general.pulse_info.pulses == []
    assert general.reputation == 0
    assert general.country_name is None


@pytest.mark.parametrize(
    "fixture, indicator, otx_type",
    [
        ("general_domain_known.json", "malicious.example", "domain"),
        ("general_url_known.json", "http://malicious.example/payload.bin?id=1", "url"),
    ],
)
def test_general_should_parse_domains_and_urls_without_reputation(
    fixture, indicator, otx_type
):
    # Given the OTX answer for a domain or a URL: no reputation, no geolocation
    response = _load(fixture)

    # When validating it
    general = OtxGeneral.model_validate(response)

    # Then the missing keys are None and the pulse is read
    assert general.indicator == indicator
    assert general.type == otx_type
    assert general.reputation is None
    assert general.country_name is None
    assert general.pulse_info.count == 1
    assert len(general.pulse_info.pulses) == 1


@pytest.mark.parametrize(
    "pulse_info, expected",
    [
        ({"count": 2}, True),
        ({"count": 1}, True),
        ({"count": 0}, False),
        ({"count": -1}, False),
        ({"count": None}, False),
        ({}, False),
    ],
)
def test_pulse_info_is_known_only_when_the_count_is_positive(pulse_info, expected):
    # Given a pulse_info block with a positive, zero, negative, null or missing count
    # When reading is_known
    # Then only a positive count means that OTX knows the indicator
    assert OtxPulseInfo.model_validate(pulse_info).is_known is expected


def test_pulse_should_normalise_the_fields_of_a_real_pulse():
    # Given the first pulse of a known IPv4
    pulse_data = _load("general_ipv4_known.json")["pulse_info"]["pulses"][0]

    # When validating it
    pulse = OtxPulse.model_validate(pulse_data)

    # Then the lists are cleaned, split and deduplicated, the dates are UTC
    assert pulse.id == "6a0000000000000000000001"
    assert pulse.tlp == "white"
    assert pulse.adversary is None
    assert pulse.tags == ["webscanner", "bruteforce", "web app attack", "ssh", "SSH"]
    assert pulse.malware_families == ["ExampleBot"]
    assert pulse.attack_ids == ["T1027"]
    assert pulse.industries == ["Legal", "Financial", "Healthcare"]
    assert pulse.targeted_countries == ["Tanzania, United Republic of", "Netherlands"]
    assert pulse.created == datetime(2018, 2, 10, 0, 36, 0, 396000, timezone.utc)
    assert pulse.modified == datetime(2018, 3, 12, 10, 15, 30, tzinfo=timezone.utc)


def test_pulse_should_keep_an_adversary_name():
    # Given a pulse that names an adversary
    pulse_data = _load("general_ipv4_known.json")["pulse_info"]["pulses"][1]

    # When validating it
    pulse = OtxPulse.model_validate(pulse_data)

    # Then the adversary is kept and the empty description is dropped
    assert pulse.adversary == "Example Group"
    assert pulse.description is None
    assert pulse.tags == []


def test_pulse_should_use_the_display_name_of_a_malware_family():
    # Given a family whose display name differs from its id
    pulse_data = _load("general_url_known.json")["pulse_info"]["pulses"][0]

    # When validating the pulse
    pulse = OtxPulse.model_validate(pulse_data)

    # Then the display name is kept
    assert pulse.malware_families == ["Example Loader"]


@pytest.mark.parametrize("field", ["tags", "industries", "malware_families"])
def test_pulse_lists_should_be_empty_when_null_or_missing(field):
    # Given a pulse whose list is null, and one without the list
    with_null = OtxPulse.model_validate({field: None})
    without = OtxPulse.model_validate({})

    # When reading the list
    # Then both are empty lists
    assert getattr(with_null, field) == []
    assert getattr(without, field) == []


def test_pulse_should_accept_plain_strings_for_malware_families_and_attack_ids():
    # Given malware families and ATT&CK IDs given as plain strings
    pulse = OtxPulse.model_validate(
        {"malware_families": ["Alpha", " Alpha ", "Beta"], "attack_ids": ["T1059"]}
    )

    # When reading them
    # Then they are kept as is, stripped and deduplicated
    assert pulse.malware_families == ["Alpha", "Beta"]
    assert pulse.attack_ids == ["T1059"]


def test_pulse_should_fall_back_on_the_id_of_a_malware_family():
    # Given a family object without display name
    pulse = OtxPulse.model_validate(
        {
            "malware_families": [
                {"id": "OnlyId", "display_name": "", "target": None},
                {"id": "Other"},
            ]
        }
    )

    # When reading them
    # Then the id is used
    assert pulse.malware_families == ["OnlyId", "Other"]


def test_pulse_should_drop_unreadable_list_items():
    # Given lists holding empty, null, numeric and object items without usable key
    pulse = OtxPulse.model_validate(
        {
            "tags": ["", "  ", None, 12, {"a": 1}, "ok"],
            "malware_families": [{}, {"id": None}, None, 3, "Fam"],
            "attack_ids": [{"name": "No id"}, "", None, {"id": "T1190"}],
            "targeted_countries": [None, "France", ""],
        }
    )

    # When reading them
    # Then only the readable items remain
    assert pulse.tags == ["ok"]
    assert pulse.malware_families == ["Fam"]
    assert pulse.attack_ids == ["T1190"]
    assert pulse.targeted_countries == ["France"]


def test_pulse_should_treat_a_bare_string_as_a_single_item_and_ignore_other_types():
    # Given list fields holding a bare string, a number and a mapping
    pulse = OtxPulse.model_validate(
        {"tags": "a, b", "industries": 5, "targeted_countries": {"x": "y"}}
    )

    # When reading them
    # Then a string is one item (and split for tags), the others are ignored
    assert pulse.tags == ["a", "b"]
    assert pulse.industries == []
    assert pulse.targeted_countries == []


def test_pulse_should_convert_dates_to_utc():
    # Given dates that are naive, in UTC with Z and in another offset
    pulse = OtxPulse.model_validate(
        {"created": "2018-02-10T00:36:00", "modified": "2018-02-10T02:36:00+02:00"}
    )
    pulse_z = OtxPulse.model_validate({"created": "2018-02-10T00:36:00Z"})
    pulse_dt = OtxPulse.model_validate(
        {"created": datetime(2018, 2, 10, 0, 36), "modified": datetime(2018, 2, 10)}
    )

    # When reading them
    # Then they are all timezone-aware UTC datetimes
    assert pulse.created == datetime(2018, 2, 10, 0, 36, tzinfo=timezone.utc)
    assert pulse.modified == datetime(2018, 2, 10, 0, 36, tzinfo=timezone.utc)
    assert pulse.modified.utcoffset() == timedelta(0)
    assert pulse_z.created == datetime(2018, 2, 10, 0, 36, tzinfo=timezone.utc)
    assert pulse_dt.created == datetime(2018, 2, 10, 0, 36, tzinfo=timezone.utc)
    assert pulse_dt.modified == datetime(2018, 2, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "  ",
        "not a date",
        12345,
        "0001-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59-01:00",
    ],
)
def test_pulse_should_use_none_for_an_unreadable_date(value):
    # Given an unreadable date
    pulse = OtxPulse.model_validate({"created": value, "modified": value})

    # When reading it
    # Then it is None, the pulse is still usable
    assert pulse.created is None
    assert pulse.modified is None


def test_pulse_should_convert_a_numeric_id_to_text():
    # Given a pulse with a numeric id and a boolean one
    # When validating them
    # Then the numeric id becomes text and the boolean is dropped
    assert OtxPulse.model_validate({"id": 42}).id == "42"
    assert OtxPulse.model_validate({"id": True}).id is None


def test_pulse_should_ignore_unknown_fields_and_be_frozen():
    # Given a pulse with fields the model does not know
    pulse = OtxPulse.model_validate({"name": "N", "indicator_count": 5, "foo": "bar"})

    # When reading and changing it
    # Then unknown fields are ignored and the model is immutable
    assert pulse.name == "N"
    assert not hasattr(pulse, "foo")
    with pytest.raises(ValidationError):
        pulse.name = "other"


def test_pulse_info_should_default_on_null_values():
    # Given a pulse_info with null count and pulses
    pulse_info = OtxPulseInfo.model_validate({"count": None, "pulses": None})

    # When reading it
    # Then it holds no pulse
    assert pulse_info.count == 0
    assert pulse_info.pulses == []


def test_general_should_default_on_null_pulse_info_and_empty_geolocation():
    # Given an answer with a null pulse_info and empty geolocation strings
    general = OtxGeneral.model_validate(
        {"pulse_info": None, "city": "", "region": "  ", "country_name": " France "}
    )

    # When reading it
    # Then empty values are None and the pulse info is empty
    assert general.pulse_info.count == 0
    assert general.city is None
    assert general.region is None
    assert general.country_name == "France"


def test_general_should_be_valid_without_any_field():
    # Given an empty answer
    # When validating it
    general = OtxGeneral.model_validate({})

    # Then it is an unknown indicator
    assert general.pulse_info.count == 0
    assert general.reputation is None


@pytest.mark.parametrize(
    "body",
    [
        [],
        "not an object",
        {"pulse_info": "oops"},
        {"pulse_info": {"count": "many"}},
        {"pulse_info": {"pulses": "oops"}},
    ],
)
def test_general_should_reject_a_wrong_shape(body):
    # Given a body that is not an OTX general answer
    # When validating it
    # Then it is rejected
    with pytest.raises(ValidationError):
        OtxGeneral.model_validate(body)


@pytest.mark.parametrize(
    "value", ["bad", "N/A", "", 0.5, float("nan"), True, {"a": 1}, [1], None]
)
def test_general_should_use_none_for_an_unreadable_reputation(value):
    # Given an answer whose reputation is not a readable integer
    # When validating it
    general = OtxGeneral.model_validate({"reputation": value})

    # Then the reputation is None, the answer is still usable
    assert general.reputation is None


@pytest.mark.parametrize("value, expected", [(3, 3), (0, 0), (2.0, 2), (" 4 ", 4)])
def test_general_should_keep_a_readable_reputation(value, expected):
    # Given a reputation that is an integer, a whole number or its text
    # When validating it
    # Then it is read as an integer
    assert OtxGeneral.model_validate({"reputation": value}).reputation == expected


def test_pulse_info_should_drop_the_pulses_that_are_not_objects():
    # Given pulses holding null, text, number and list items among objects
    pulse_info = OtxPulseInfo.model_validate(
        {
            "count": 5,
            "pulses": [None, {"name": "A"}, "oops", 3, [], {"name": "B"}],
        }
    )

    # When reading them
    # Then only the objects remain
    assert [pulse.name for pulse in pulse_info.pulses] == ["A", "B"]
    assert pulse_info.count == 5


def test_pulse_info_should_reject_pulses_that_are_not_a_list():
    # Given pulses that are a mapping
    # When validating it
    # Then it is rejected: only items of a list are dropped
    with pytest.raises(ValidationError):
        OtxPulseInfo.model_validate({"pulses": {"name": "A"}})
